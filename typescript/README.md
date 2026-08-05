# hearth-chain — TypeScript implementation

TypeScript implementation of the hearth-chain crypto foundation. See the
[root README](../README.md) for the language-independent cryptographic design
(schemes, key derivation, addresses, replay protection). This one covers the
TypeScript tooling and layout.

- **Node.js 24+** (runs TypeScript natively via type stripping — no build step),
  **TypeScript 5.9** for type-checking only.
- **Pure TypeScript, no libsodium/WASM.** The idiomatic choice: the edwards25519
  group/scalar arithmetic the VRF needs comes from
  [`@noble/curves`](https://github.com/paulmillr/noble-curves), Ed25519 signatures
  from the same, and hashing/HMAC/PBKDF2 from
  [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) — audited,
  zero-dependency, constant-time. BLS `mod r` uses native `BigInt`; BIP-39 NFKD
  uses the built-in `String.prototype.normalize`.
- **HPKE (RFC 9180)** (`hpke`, `apikeyenvelope`) for sealing a secret to a
  published public key — see [Sealing a secret to a public key](#sealing-a-secret-to-a-public-key).
  X25519 comes from `@noble/curves`; the AES-GCM and ChaCha20-Poly1305 AEADs
  from [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers) (same
  publisher family, added alongside the existing `@noble/curves`/`@noble/hashes`
  dependencies); HKDF is built on `@noble/hashes`' HMAC-SHA256 like everything else.

## Prerequisites

- Node.js 24+ (developed on 24.15). It executes `.ts` directly and ships a
  built-in test runner, so there is no bundler or transpile step.

## Run

```bash
npm install
npm test          # RFC 9381 / 9180 / SLIP-0010 / BIP-39 / EIP-2333 / BIP-350 vectors + cross-parity
npm run demo      # the sample app with a demo mnemonic
npm run typecheck # tsc --noEmit

# HPKE example: seal an API key to an enclave's public key, open it, try to forge it
npm run hpke-example

# custom inputs:
node src/demo.ts "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" aGVsbG8= d29ybGQ=
```

## Layout

```
package.json / tsconfig.json    Node 24 + TypeScript 5.9 (type-check only)
src/
  primitives.ts  hashing/HMAC + edwards25519 group/scalar ops (@noble)
  bip39.ts       mnemonic validation + PBKDF2 seed (reads english.txt)
  slip10.ts      SLIP-0010 ed25519 hierarchical derivation
  bls.ts         BLS12-381 key derivation (EIP-2333 / EIP-2334)
  ed25519.ts     KeyPair from seed, sign/verify, VRF scalar/nonce
  ecvrf.ts       RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI
  bech32m.ts     BIP-350 codec
  address.ts     account addresses + Network
  keytree.ts     the three role keys from one seed
  x25519.ts      RFC 7748 over raw keys (@noble/curves)
  hpke.ts        RFC 9180 single-shot seal/open, base mode
  apikeyenvelope.ts  the API-key wire format on top of hpke.ts
  hex.ts         hex helpers
  index.ts       namespaced re-exports
  demo.ts        the sample app
  hpke-example.ts    seal an API key to an enclave key
test/vectors.test.ts             official vectors + cross-parity with the other builds
test/hpke.test.ts                RFC 9180 A.1/A.2 vectors + tamper/rejection coverage
test/apikeyenvelope.test.ts      envelope round-trip / tamper / expiry
```

## Sealing a secret to a public key

`apikeyenvelope` covers the case this library was extended for: shipping a
32-character API key to a confidential VM (Intel TDX) that generated an X25519
keypair inside the TD and bound the public key into its attestation report.

```typescript
import { apikeyenvelope as env } from "@hearth/crypto";

// client — after verifying the quote and that REPORTDATA == SHA-512(ctx || pk)
const apiKey = env.randomApiKey();
const envelope = env.seal(
  enclavePublicKey,
  apiKey,
  env.metadata("prod/ingest-api", new Date(Date.now() + 24 * 3600 * 1000)),
);

// enclave
const opened = env.open(enclaveSecretKey, envelope);
use(opened.apiKey);
env.wipe(opened);
```

Ciphersuite: **DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305**
(0x0020 / 0x0001 / 0x0003), HPKE **base mode**, single-shot. AES-128-GCM and
AES-256-GCM are also available through `hpke.Suite`. The envelope is 124 bytes
for a 15-character key id: a 20-byte fixed header, the metadata, the 32-byte
encapsulated key, and 48 bytes of ciphertext. Everything before the encapsulated
key is the AEAD's additional data, so the suite ids, the recipient fingerprint,
the key id and the expiry are all covered by the tag.

Use `hpke` directly for any other payload; `apikeyenvelope` only adds the fixed
`info` string, the frame, and the 32-alphanumeric-character check.

**This is only half of the problem.** HPKE gets the key to whoever holds the
private key; it says nothing about *who that is*. The client must verify the TDX
quote — signature chain to Intel's PCS, TCB status, `MRTD`/`RTMR`
measurements — and check that the public key it is about to seal to is the one
hashed into `REPORTDATA`, before calling `seal`. Base mode also leaves the sender
unauthenticated and the ciphertext replayable for as long as the recipient's
private key lives: authorize delivery at the transport layer, keep the TD's
keypair ephemeral per boot, and set an expiry.

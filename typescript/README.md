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

## Prerequisites

- Node.js 24+ (developed on 24.15). It executes `.ts` directly and ships a
  built-in test runner, so there is no bundler or transpile step.

## Run

```bash
npm install
npm test          # RFC 9381 / SLIP-0010 / BIP-39 / EIP-2333 / BIP-350 vectors + cross-parity
npm run demo      # the sample app with a demo mnemonic
npm run typecheck # tsc --noEmit

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
  hex.ts         hex helpers
  index.ts       namespaced re-exports
  demo.ts        the sample app
test/vectors.test.ts            official vectors + cross-parity with the other builds
```

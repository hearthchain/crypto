# hearth-chain

A reference crypto foundation for a blockchain that uses **standard, Ledger-native
cryptography** for signatures, **ECVRF (RFC 9381)** for miner election, and **BLS12-381**
for stake-weighted finality — all derived from a single BIP-39 mnemonic.

## Implementations

Five implementations, **byte-for-byte compatible** (same test vectors, same derived keys and
addresses — cross-checked in each test suite):

| | Directory | Stack |
|---|---|---|
| Java | [`java/`](java/README.md) | Java 25 + Maven; libsodium via Panama FFI, pure-JVM fallback |
| Python | [`python/`](python/README.md) | uv + PyNaCl (libsodium) |
| Go | [`go/`](go/README.md) | Go 1.26; pure Go (`filippo.io/edwards25519`), no cgo |
| Rust | [`rust/`](rust/README.md) | Rust 2024; pure Rust (`curve25519-dalek`, `ed25519-dalek`) |
| TypeScript | [`typescript/`](typescript/README.md) | Node 24 + TypeScript; pure TS (`@noble/curves`, `@noble/hashes`) |

This document describes the language-independent design; see each subproject's README for
build/run instructions.

> **Parity status.** Java and Rust implement the address encoding and the seedless key
> imports described below, and pin the same vectors. Go, Python and TypeScript still emit
> the older `hrthm`/`hrtht` address form with a `0x00` version byte and have no seedless
> import; aligning them is pending. Until then the byte-for-byte claim holds for all three
> across everything except addresses and key import.

Each implementation embeds its own copy of the immutable BIP-39 English wordlist (Go's
`go:embed` can't cross directories or follow symlinks, so a single shared file isn't
practical). Drift is prevented by a checksum guard: every suite asserts the wordlist's
SHA-256 matches the official value, and [`scripts/check-wordlists.sh`](scripts/check-wordlists.sh)
checks all five copies at once (wire it into CI).

## Cryptographic choices

| Concern            | Choice                                                         | Why |
|--------------------|---------------------------------------------------------------|-----|
| Signatures         | **Ed25519 / EdDSA (RFC 8032)**                                 | The modern standard signature scheme; supported **natively on Ledger** devices. |
| Miner election VRF | **ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381, suite 0x03)**       | Standardized VRF sharing Ed25519's curve; derived from a **separate** key (see below). |
| Finality           | **BLS12-381 aggregate signatures** (key derivation via EIP-2333; signing so far only in Java) | Stake-weighted finality: aggregate any voter subset whose balance > 50%. |
| Mnemonic → seed    | **BIP-39** (PBKDF2-HMAC-SHA512, 2048 iters)                    | Standard wallet seed phrases. |
| Key derivation     | **SLIP-0010 ed25519** (hardened-only) + **EIP-2333** for BLS   | The HD schemes Ledger / eth2 use for their respective curves. |
| Secret delivery    | **HPKE (RFC 9180)**, DHKEM(X25519, HKDF-SHA256) + ChaCha20-Poly1305 | Sealing a secret (an API key) to a public key an enclave published — same curve family, standardized. Implemented in all five ([`ApiKeyEnvelope`](java/README.md#sealing-a-secret-to-a-public-key)/[`apikeyenvelope`](rust/README.md#sealing-a-secret-to-a-public-key)), verified against the RFC 9180 A.1/A.2 vectors. |

Curve, hash and VRF group arithmetic run on **libsodium** (Java, Python) or audited
pure-language crates — **`curve25519-dalek`** (Rust), **`filippo.io/edwards25519`** (Go), and
**`@noble/curves`** (TypeScript); the HMAC-based constructions (PBKDF2, SLIP-0010, HKDF) use
each language's standard library.

## Key derivation & separation

The signing key and the VRF key are derived at **different hardened SLIP-0010 paths**, so
their secret scalars are unrelated. Sharing one Ed25519 key between EdDSA and ECVRF is *not*
safe without care: because both are Schnorr-type schemes over the same scalar with the same
nonce prefix, an attacker who can get the miner to sign a message equal to the VRF's
hash-to-curve point `H` forces a nonce collision and recovers the key. Separate keys make that
structurally impossible. BLS finality keys live in their own EIP-2333 tree (different curve).

One mnemonic, three independent keys:

| Role | Curve / scheme | Path |
|---|---|---|
| Transaction signing | ed25519 / SLIP-0010 | `m/44'/9381'/account'/0'/0'` |
| VRF (miner election) | ed25519 / SLIP-0010 | `m/44'/9381'/account'/1'/0'` |
| BLS finality | BLS12-381 / EIP-2333 | `m/12381/9381/account/0` |

ed25519 paths are all-hardened; BLS paths carry **no** `'` — EIP-2333 has no hardened/
non-hardened distinction, it is hardened-equivalent throughout. (`9381` is a placeholder
coin type; register a real SLIP-0044 value.) BLS key *derivation* is implemented in all five;
BLS *signing*/aggregation/PoP needs a pairing backend, and so far only [`java/`](java/README.md)
has one (`BlsKey`, on `blst-java`) — the eth2-standard ciphersuite (minimal-pubkey-size,
proof-of-possession) plus a Basic (unaugmented) one for callers doing their own out-of-band
proof of possession. The other four implementations remain derivation-only.

## Addresses

```
address = Bech32m(hrp, SHA-256(publicKey)[0..20])
```

- **SHA-256, truncated to 20 bytes**: standard 160-bit account id, reproducible across
  implementations. These 20 bytes *are* the identity — the transaction recipient field, state
  keys, and address equality all use them. There is no version byte; an address is the account
  hash and nothing else.
- **Bech32m** (BIP-350): strong typo detection, human-readable prefix, lowercase, QR-friendly.
- **The network is not part of the identity.** It only selects the HRP when a string is
  rendered or parsed: `hrth` (mainnet), `thrth` (testnet). One account is one address on every
  network, so the HRP is supplied at that boundary rather than stored in the address. Example,
  for the demo signing key: `hrth19uvmpe6ll76dav0mvk06d35att3wk7a7gm8xwm` and
  `thrth19uvmpe6ll76dav0mvk06d35att3wk7a7vvkkh7` — 43 characters, same account.

### Networks and replay protection

The HRP is a **UX guard** (a wallet refuses a `thrth…` address on mainnet) — it is **not**
replay protection, because a replay attacker rebroadcasts signed bytes rather than typing an
address. Replay protection belongs in the signed transaction, and is the plan for the tx type:

- **cross-network replay** → include a network id / domain-separation tag in the signed
  payload (à la EIP-155 / Cosmos `chain_id`), so a mainnet signature fails on testnet;
- **same-network replay** → a per-account nonce (account model) or spent-UTXO set.

## Signing keys

A signing key is the pair EdDSA actually uses: the secret scalar `a` and the nonce prefix. A
seed is a compact way to *generate* that pair by hashing (RFC 8032 §5.1.5), not a different
kind of key. So a key derived from a mnemonic and a key imported from a raw scalar are the
same type, sign through the same call, and are indistinguishable to a verifier — the flow from
key to signature does not branch on where the key came from.

| Entry | Takes |
|---|---|
| `fromSeed` | a 32-byte seed — the SLIP-0010 node key the key tree derives from a mnemonic |
| `fromExpandedKey` | `scalar[32] ‖ noncePrefix[32]` |
| `fromScalar` | `scalar[32]`; the prefix is derived as `SHA-512(DST ‖ scalar)[32..64]`, with DST = `hearth-chain/ed25519-scalar-expand/v1` |

Export is the mirror of the second: `toExpandedKey()` returns `scalar ‖ noncePrefix`. Keys move
as bytes — there is no text encoding for a secret key, and reading one in from a file, a config
value or an operator's paste is the caller's business.

The seedless entries exist because some keys **cannot** have a seed: no seed hashes to a
chosen scalar. The motivating case is vanity-address search, where candidates are walked by
repeated point addition (`A_i = A_{i-1} + B`) — one addition per candidate instead of a full
scalar multiplication, roughly two orders of magnitude cheaper — which produces a scalar
directly. A generator like that should emit the bare 32-byte scalar and let `fromScalar`
expand it, which is what [`hearth-vanity`](rust/README.md#vanity-addresses) does.

What a seedless key cannot do is anything that needs the seed *as such*: it has no mnemonic
and no SLIP-0010 path, so it cannot produce the account's sibling VRF key (which lives at a
different path anyway). Signing, addresses and export are identical.

An imported scalar is used **verbatim** — not clamped, and not required to be reduced mod L.
Clamping guards X25519's cofactor and a ladder's timing, not the signature equation, and a
scalar reached by point addition has no reason to satisfy it; conversely a seed-derived scalar
always sits above L, so demanding canonical scalars would stop a seed key round-tripping at
all. Rejected: a scalar with the high bit set, or one that is zero mod L (its public key is
the identity point, which verification rejects for every signature).

The one operation that follows the scalar's shape rather than the key's provenance is the
ed25519→X25519 conversion used for HPKE: it needs a clamped scalar and refuses otherwise,
because X25519 re-clamps whatever secret it is handed and an unclamped one would silently act
as a *different* key from the public key returned with it. A seed-derived key therefore still
converts after a round trip through the expanded form.

**The nonce prefix is secret key material, not a label.** EdDSA's per-signature nonce is
`r = SHA-512(prefix ‖ message)`: anyone who learns the prefix learns `r` for every message the
key signs and recovers `a` from a single signature as `(S − r)/k`. A generator emitting
expanded keys must draw the prefix from a CSPRNG — never from the search counter, the
candidate index, or anything else a stranger can guess. `fromScalar` removes that trap by
deriving the prefix from the secret scalar itself.

### Vanity addresses

[`rust/`](rust/README.md#vanity-addresses) ships `hearth-vanity`, a grinder for addresses
starting with a chosen string:

```bash
cd rust && cargo run --release --features vanity --bin hearth-vanity -- --prefix hearth
# hrth1hearthkcfl46zs56n6nrmhrksr5c7g6zyq0khz
```

It walks scalars rather than seeds and batches the field inversion across a window of
candidates, reaching ~6.7 M keys/s per core — 64 M/s on a 13-thread M4-class machine, where a
6-character pattern lands in seconds and an 8-character one in about five hours. Since an
address carries no version byte, all 32 characters after the separator are free and *n*
characters cost `32^n`. Every hit is re-derived through the ordinary library path before it is
reported, and starting scalars come from the OS CSPRNG — the `profanity` generator's 32-bit
seed is what made every address it produced brute-forceable.

## The sample app

All five implementations ship the same demo. Given a BIP-39 mnemonic it:

1. derives the three role keys from one seed (signing + VRF ed25519 keys at distinct
   SLIP-0010 paths, and the BLS12-381 finality key via EIP-2333);
2. takes a base64 byte string and **signs** it with the **signing** key;
3. **verifies** the signature with the signing public key (and shows a tampered message failing);
4. takes a base64 byte string as VRF input `alpha`, **VRF-signs** it with the **VRF** key to a
   proof `pi`, derives the VRF value `beta`, and verifies the proof.

Run it via [`java/`](java/README.md) (`mvn -q compile exec:exec`), [`python/`](python/README.md)
(`uv run hearth-demo`), [`go/`](go/README.md) (`go run ./cmd/hearth-demo`), [`rust/`](rust/README.md)
(`cargo run --example hearth-demo`), or [`typescript/`](typescript/README.md)
(`npm run demo`); all five print identical values for the same inputs.

## Status / next steps

This is a crypto foundation sketch, not a chain yet. Natural next pieces:
transaction & block types with a domain-separated signing envelope
(`sign(SHA-512(DST ‖ networkId ‖ bytes))`), a leader-election rule over `beta`, porting BLS
finality signing/aggregation/PoP (a `blst`-equivalent pairing backend) from Java to the other
four implementations, a P2P layer, and storage. On the parity side: porting the address
encoding and [seedless key imports](#signing-keys) to Go, Python and TypeScript, which Java
and Rust already share.

HPKE (`Hpke`/`hpke` + `ApiKeyEnvelope`/`apikeyenvelope`) now ships in all five implementations,
each checked against the same RFC 9180 A.1/A.2 vectors — the byte-for-byte parity claim above
covers it too.

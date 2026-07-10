# hearth-chain — Scala implementation

Scala 3 implementation of the hearth-chain crypto foundation. See the
[root README](../README.md) for the language-independent cryptographic design
(schemes, key derivation, addresses, replay protection).

- **sbt** 1.11.x, **Scala** 3.8.4, JDK 22+.
- Curve/hash primitives run on **libsodium** via the Java 22+ Foreign Function &
  Memory API (Panama), with a **pure-JVM fallback** so it runs anywhere.

## Layout

```
build.sbt                         sbt 1.11.x, Scala 3.8.4
src/main/scala/hearth/crypto/
  CryptoBackend.scala  the primitive interface + Crypto facade (picks a backend)
  SodiumBackend.scala  libsodium backend via Panama FFI (fast path)
  JvmBackend.scala     pure-JVM backend (JDK digests/HMAC + BigInteger group)
  Ed25519Math.scala    edwards25519 field/group arithmetic (fallback only)
  Bip39.scala          mnemonic validation + PBKDF2 seed
  Slip10.scala         SLIP-0010 ed25519 hierarchical derivation
  Bls.scala            BLS12-381 key derivation (EIP-2333 / EIP-2334)
  KeyTree.scala        the three role keys from one seed (signing / VRF / BLS)
  Ed25519.scala        keypair from seed, sign/verify, VRF scalar/nonce derivation
  Ecvrf.scala          RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI (prove / verify / proof_to_hash)
  Bech32m.scala        BIP-350 Bech32m codec
  Address.scala        account addresses + Network (mainnet/testnet)
  Hex.scala            hex helpers
src/main/scala/hearth/app/Demo.scala   the sample app
src/test/scala/hearth/CryptoSpec.scala RFC 9381 + SLIP-0010 + BIP-39 vectors, run on BOTH backends
src/test/scala/hearth/BlsSpec.scala    EIP-2333 vectors + KeyTree role separation
```

## Crypto backends

Everything is expressed against a `CryptoBackend` interface, threaded as a Scala 3
`using` parameter (default = `Crypto`, which auto-selects):

- **`SodiumBackend`** — libsodium via Panama. Fast, audited, constant-time. Used when
  the native library is found.
- **`JvmBackend`** — pure JVM (JDK `MessageDigest`/`Mac` + `BigInteger` edwards25519).
  No native dependency; used automatically when libsodium is absent. Correctness-first,
  *not* constant-time.

Both are byte-for-byte identical (verified by the test suite, which runs the RFC vectors
on each and cross-checks them). Force one with `HEARTH_CRYPTO_BACKEND=sodium|jvm`.

## Prerequisites

- JDK 22+ (developed on Temurin 25). The FFM API needs no preview flags.
- **libsodium** is *optional* — without it the app transparently uses the pure-JVM
  backend. For the fast, audited native path install it:
  - macOS: `brew install libsodium`
  - Debian/Ubuntu: `apt install libsodium23`
  - If it's in a non-standard location, set `HEARTH_SODIUM_LIB=/path/to/libsodium.dylib`.

## Run

```bash
sbt test          # verifies against official RFC 9381 / SLIP-0010 / BIP-39 / EIP-2333 vectors
sbt run           # runs the sample app (hearth.app.Demo) with a demo mnemonic

# custom inputs: sbt "run <mnemonic> <messageBase64> <alphaBase64>"
sbt 'run "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" aGVsbG8= d29ybGQ='
```

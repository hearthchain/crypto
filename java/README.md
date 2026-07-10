# hearth-chain — Java implementation

Java implementation of the hearth-chain crypto foundation, packaged as a
reusable library (`tech.hearth:hearth-chain-crypto`). See the
[root README](../README.md) for the language-independent cryptographic design
(schemes, key derivation, addresses, replay protection). This one covers the Java
tooling and layout.

- **Java 25**, **Maven**. No dependencies beyond the JDK (JUnit only for tests).
- Curve/hash primitives run on **libsodium** via the **Panama** Foreign Function &
  Memory API, with a **pure-JVM fallback** (JDK digests/HMAC + `BigInteger`
  edwards25519). HMAC-based constructions (PBKDF2, SLIP-0010, HKDF) use the JDK.

## Backends

Everything is expressed against the `CryptoBackend` interface, passed explicitly
(call `Crypto.defaultBackend()` for the auto-selected one):

- **`SodiumBackend`** — libsodium via Panama. Fast, audited, constant-time. Used
  when the native library is found.
- **`JvmBackend`** — pure JVM (`MessageDigest`/`Mac` + `BigInteger` edwards25519).
  No native dependency; used automatically when libsodium is absent. Not constant-time.

Both are byte-for-byte identical (the test suite runs the RFC vectors on each and
cross-checks them). Force one with `HEARTH_CRYPTO_BACKEND=sodium|jvm`.

## Prerequisites

- JDK 22+ (developed on Temurin 25). The FFM API needs no preview flags.
- **libsodium** is *optional* — without it the library uses the pure-JVM backend.
  For the fast native path: `brew install libsodium` (macOS) /
  `apt install libsodium23` (Debian/Ubuntu), or set `HEARTH_SODIUM_LIB`.

## Run

```bash
mvn test                       # RFC 9381 / SLIP-0010 / BIP-39 / EIP-2333 / BIP-350 vectors, on BOTH backends
mvn -q compile exec:exec       # runs the sample app (tech.hearth.app.Demo)

# custom inputs (after `mvn compile`):
java --enable-native-access=ALL-UNNAMED -cp target/classes tech.hearth.app.Demo \
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" aGVsbG8= d29ybGQ=
```

## Layout

```
pom.xml                                   Java 25, Maven, JUnit 5
src/main/java/tech/hearth/crypto/
  CryptoBackend.java   the primitive interface
  SodiumBackend.java   libsodium backend via Panama FFI (fast path)
  JvmBackend.java      pure-JVM backend (JDK digests/HMAC + BigInteger group)
  Ed25519Math.java     edwards25519 field/group arithmetic (fallback only)
  Crypto.java          backend selection + shared sizes
  Bip39.java           mnemonic validation + PBKDF2 seed
  Slip10.java          SLIP-0010 ed25519 hierarchical derivation
  Bls.java             BLS12-381 key derivation (EIP-2333 / EIP-2334)
  Ed25519.java         keypair from seed, sign/verify, VRF scalar/nonce
  Ecvrf.java           RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI
  Bech32m.java         BIP-350 codec
  Address.java         account addresses + Network
  KeyTree.java         the three role keys from one seed
  Hex.java             hex helpers
src/main/java/tech/hearth/app/Demo.java   the sample app
src/test/java/tech/hearth/crypto/CryptoVectorsTest.java  vectors on both backends + cross-parity
```

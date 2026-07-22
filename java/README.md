# hearth-chain — Java implementation

Java implementation of the hearth-chain crypto foundation, packaged as a
reusable library (`tech.hearth:crypto`). See the
[root README](../README.md) for the language-independent cryptographic design
(schemes, key derivation, addresses, replay protection). This one covers the Java
tooling and layout.

- **Java 25**, **Maven**.
- Curve/hash primitives run on **libsodium** via the **Panama** Foreign Function &
  Memory API, with a **pure-JVM fallback** (JDK digests/HMAC + `BigInteger`
  edwards25519). HMAC-based constructions (PBKDF2, SLIP-0010, HKDF) use the JDK.
- **BLS12-381 signatures/aggregation** (`BlsKey`) run on **blst** via
  `com.wavesplatform:blst-java` (JNI) — the one runtime dependency, needed only
  for BLS signing; ed25519/VRF/derivation stay dependency-free. Ciphersuite:
  minimal-pubkey-size, proof-of-possession (eth2). BLS keys are the EIP-2333
  scalars loaded verbatim (`SecretKey.from_bendian`), not re-derived.

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
mvn test                       # RFC 9381 / SLIP-0010 / BIP-39 / EIP-2333 / BIP-350 vectors + BLS sign/aggregate
mvn -q compile exec:exec       # sample app (tech.hearth.app.Demo)

# BLS finality example: derive N validator keys, sign, aggregate, verify
mvn -q compile exec:exec -DmainClass=tech.hearth.app.BlsExample

# custom Demo inputs (after `mvn compile`):
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
  BlsKey.java          BLS12-381 signing / aggregation / verify (blst)
  SigningKey.java      Ed25519 signing key (role-typed)
  VrfKey.java          Ed25519 VRF key (role-typed; no EdDSA sign)
  Ed25519.java         signature verification + VRF scalar helpers
  Ecvrf.java           RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI
  Bech32m.java         BIP-350 codec
  Address.java         network-independent account identity + Network
  KeyTree.java         the three role keys from one seed
  Hex.java             hex helpers
src/main/java/tech/hearth/app/Demo.java        the sample app
src/main/java/tech/hearth/app/BlsExample.java  BLS derive / sign / aggregate / verify
src/test/java/tech/hearth/crypto/CryptoVectorsTest.java   vectors on both backends + cross-parity
src/test/java/tech/hearth/crypto/BlsSignatureTest.java    BLS sign / aggregate / PoP
```

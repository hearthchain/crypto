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
  minimal-pubkey-size, proof-of-possession (eth2) by default (`sign`/`verify`/
  `fastAggregateVerify`), plus a Basic ciphersuite (`signBasic`/`verifyBasic`/
  `fastAggregateVerifyBasic`) for callers doing their own out-of-band
  proof-of-possession. BLS keys are the EIP-2333
  scalars loaded verbatim (`SecretKey.from_bendian`), not re-derived.
- **HPKE (RFC 9180)** (`Hpke`, `ApiKeyEnvelope`) for sealing a secret to a
  published public key — see [Sealing a secret to a public key](#sealing-a-secret-to-a-public-key).
  Dependency-free: the group operation is the JDK's `XDH` provider, the AEAD is
  `javax.crypto`, and HMAC goes through `CryptoBackend` like everything else.
- **TDX DCAP quote authentication** (`TdxQuote`) verifies the offline signature
  chain of an Intel TDX v4 quote and binds a public key to `REPORTDATA` — see
  [Authenticating a TDX quote](#authenticating-a-tdx-quote). Dependency-free:
  ECDSA-P256 and the PCK certificate chain both run on `java.security`.

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
mvn test                       # RFC 9381 / 9180 / SLIP-0010 / BIP-39 / EIP-2333 / BIP-350 vectors + BLS sign/aggregate
mvn -q compile exec:exec       # sample app (tech.hearth.app.Demo)

# BLS finality example: derive N validator keys, sign, aggregate, verify
mvn -q compile exec:exec -DmainClass=tech.hearth.app.BlsExample

# HPKE example: seal an API key to an enclave's public key, open it, try to
# forge it, then cross-check the raw HPKE layer against the Go miner's fixed
# integration vectors (internal/enclave/integration_vectors_test.go)
mvn -q compile exec:exec -DmainClass=tech.hearth.app.HpkeExample

# TDX quote authentication test: verifies a real quote captured from a
# deployed miner node against the hardcoded Intel SGX Root CA
mvn -q -Dtest=TdxQuoteTest test

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
  SigningKey.java      Ed25519 signing key (role-typed); toX25519() for the HPKE recipient key
  VrfKey.java          Ed25519 VRF key (role-typed; no EdDSA sign)
  Ed25519.java         signature verification + VRF scalar helpers
  Ecvrf.java           RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI
  Bech32m.java         BIP-350 codec
  Address.java         network-independent account identity + Network
  KeyTree.java         the three role keys from one seed
  X25519.java          RFC 7748 over raw keys (JDK XDH)
  Hpke.java            RFC 9180 single-shot seal/open, base mode
  ApiKeyEnvelope.java  the API-key wire format on top of Hpke
  Hex.java             hex helpers
src/main/java/tech/hearth/attestation/
  TdxQuote.java                    parse + authenticate a TDX v4 DCAP quote
  QuoteVerificationException.java  thrown on any parse or signature-chain failure
src/main/resources/attestation/intel-sgx-root-ca.pem   hardcoded trust anchor (Intel's real SGX Root CA)
src/main/java/tech/hearth/app/Demo.java        the sample app
src/main/java/tech/hearth/app/BlsExample.java  BLS derive / sign / aggregate / verify
src/main/java/tech/hearth/app/HpkeExample.java seal an API key to an enclave key; cross-checks the Go miner's vectors
src/test/java/tech/hearth/crypto/CryptoVectorsTest.java   vectors on both backends + cross-parity
src/test/java/tech/hearth/crypto/BlsSignatureTest.java    BLS sign / aggregate / PoP
src/test/java/tech/hearth/crypto/HpkeVectorsTest.java     RFC 9180 A.1/A.2 on both backends
src/test/java/tech/hearth/crypto/ApiKeyEnvelopeTest.java  envelope round-trip / tamper / expiry
src/test/java/tech/hearth/attestation/TdxQuoteTest.java   verifies a real captured miner quote end to end
```

## Sealing a secret to a public key

`ApiKeyEnvelope` covers the case this library was extended for: shipping a
32-character API key to a confidential VM (Intel TDX) that generated an X25519
keypair inside the TD and bound the public key into its attestation report.

```java
// client — after TdxQuote.verify(quote).bindsPublicKey(enclavePublicKey)
char[] apiKey = ApiKeyEnvelope.randomApiKey();
byte[] envelope = ApiKeyEnvelope.seal(enclavePublicKey, apiKey,
        ApiKeyEnvelope.Metadata.of("prod/ingest-api", Instant.now().plus(Duration.ofDays(1))));

// enclave
ApiKeyEnvelope.Opened opened = ApiKeyEnvelope.open(enclaveSecretKey, envelope);
use(opened.apiKey());
opened.wipe();
```

Ciphersuite: **DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305**
(0x0020 / 0x0001 / 0x0003), HPKE **base mode**, single-shot. AES-128-GCM and
AES-256-GCM are also available through `Hpke.Suite`. The envelope is 124 bytes
for a 15-character key id: a 20-byte fixed header, the metadata, the 32-byte
encapsulated key, and 48 bytes of ciphertext. Everything before the encapsulated
key is the AEAD's additional data, so the suite ids, the recipient fingerprint,
the key id and the expiry are all covered by the tag.

Use `Hpke` directly for any other payload; `ApiKeyEnvelope` only adds the fixed
`info` string, the frame, and the 32-alphanumeric-character check.

A TD that publishes a single ed25519 identity key (the one it signs with)
rather than a separate X25519 key can derive the HPKE recipient key from it:
`SigningKey.toX25519()` applies the standard ed25519-to-curve25519 conversion
(libsodium's `crypto_sign_ed25519_{pk,sk}_to_curve25519`). `HpkeExample`'s raw
HPKE section uses this to reproduce the Go miner's fixed integration vectors
(`internal/enclave/integration_vectors_test.go`) — same seed, same signature,
and it decrypts the miner's fixed envelope constant — confirming this
library's HPKE is wire-compatible with `cloudflare/circl`'s.

**This is only half of the problem.** HPKE gets the key to whoever holds the
private key; it says nothing about *who that is*. The client must verify the TDX
quote (`TdxQuote.verify`, below) and check that the public key it is about to
seal to is the one bound into `REPORTDATA`, before calling `seal`. Base mode
also leaves the sender unauthenticated and the ciphertext replayable for as
long as the recipient's private key lives: authorize delivery at the transport
layer, keep the TD's keypair ephemeral per boot, and set an expiry.

## Authenticating a TDX quote

`TdxQuote.verify` checks the offline signature chain a TDX v4 DCAP quote
carries in itself — no network access, no Intel PCS collateral:

```
quote signature ------------------ verified by --> attestation key
attestation key + qe_auth_data --- hashed into  --> QE report's report_data
QE report signature -------------- verified by --> PCK leaf certificate
PCK leaf <- PCK intermediate CA <- Intel SGX Root CA (hardcoded trust anchor)
```

```java
TdxQuote quote = TdxQuote.verify(rawQuoteBytes); // throws QuoteVerificationException on any failure

if (!quote.bindsPublicKey(enclavePublicKey)) {
    throw new IllegalStateException("quote does not bind the key we were handed");
}
// quote.mrTd() / quote.rtmr(3) are available to pin against a known-good build.
```

The trust anchor is Intel's real SGX Root CA certificate, bundled at
`src/main/resources/attestation/intel-sgx-root-ca.pem` — the same certificate
`github.com/google/go-tdx-guest`'s `verify` package embeds, which the miner
depends on (for quote *fetching*; it delegates verification to
`secretvm-cli verify quote`, see `scripts/verify-node.sh` in the miner repo).

**What this does not check:** TCB freshness (is the platform's firmware/microcode
up to date) or certificate revocation — both need live collateral from Intel
PCS. A deployment that needs a TCB verdict too still needs a live DCAP
verifier for that part; `TdxQuote` covers the half that makes the quote's
signature, and its binding to a public key, trustworthy on their own.

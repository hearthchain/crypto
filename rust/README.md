# hearth-chain — Rust implementation

Rust implementation of the hearth-chain crypto foundation. See the
[root README](../README.md) for the language-independent cryptographic design
(schemes, key derivation, addresses, replay protection). This one covers the Rust
tooling and layout.

- **Rust** (edition 2024), crate `hearth`.
- **Pure Rust, no libsodium/cgo.** The idiomatic Rust choice: the edwards25519
  group/scalar arithmetic the VRF needs comes from
  [`curve25519-dalek`](https://crates.io/crates/curve25519-dalek), Ed25519
  signatures from [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek), and
  hashing/MAC from the RustCrypto `sha2`/`hmac` crates — all audited and
  constant-time. BLS `mod r` uses `num-bigint`; BIP-39 NFKD uses
  `unicode-normalization`.
- **HPKE (RFC 9180)** (`hpke`, `apikeyenvelope`) for sealing a secret to a
  published public key — see [Sealing a secret to a public key](#sealing-a-secret-to-a-public-key).
  X25519 runs on `curve25519-dalek`'s `MontgomeryPoint` (already a dependency,
  no new crate needed); the AEADs are the RustCrypto `aes-gcm`/
  `chacha20poly1305` crates, and `rand` supplies the CSPRNG for keypairs and
  API keys.

## Prerequisites

- A recent stable Rust toolchain (edition 2024 needs rustc ≥ 1.85; developed on
  1.96). No C toolchain, no native libraries; cross-compiles cleanly.

## Run

```bash
cargo test                     # RFC 9381 / 9180 / SLIP-0010 / BIP-39 / EIP-2333 / BIP-350 vectors + cross-parity
cargo run --example hearth-demo    # the sample app with a demo mnemonic

# custom inputs:
cargo run --example hearth-demo -- \
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" aGVsbG8= d29ybGQ=

# HPKE example: seal an API key to an enclave's public key, open it, try to forge it
cargo run --example hpke-example

cargo clippy --all-targets -- -D warnings   # lints
cargo fmt --check                            # formatting
```

## Layout

```
Cargo.toml                      crate `hearth`, edition 2024
src/
  lib.rs         crate root + Error enum
  primitives.rs  hashing/HMAC + edwards25519 group/scalar ops (curve25519-dalek)
  bip39.rs       mnemonic validation + PBKDF2 seed (embeds english.txt)
  slip10.rs      SLIP-0010 ed25519 hierarchical derivation
  bls.rs         BLS12-381 key derivation (EIP-2333 / EIP-2334)
  ed25519.rs     keypair from seed, sign/verify, VRF scalar/nonce
  ecvrf.rs       RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI
  bech32m.rs     BIP-350 codec
  address.rs     account addresses + Network
  keytree.rs     the three role keys from one seed
  x25519.rs      RFC 7748 over raw keys (curve25519-dalek Montgomery ladder)
  hpke.rs        RFC 9180 single-shot seal/open, base mode
  apikeyenvelope.rs  the API-key wire format on top of hpke
  hex.rs         hex helpers
examples/hearth-demo.rs         the sample app
examples/hpke-example.rs        seal an API key to an enclave key
tests/vectors.rs                official vectors + cross-parity with the other builds
tests/hpke_vectors.rs           RFC 9180 A.1/A.2 + envelope round-trip/tamper/expiry
```

## Sealing a secret to a public key

`apikeyenvelope` covers the case this library was extended for: shipping a
32-character API key to a confidential VM (Intel TDX) that generated an X25519
keypair inside the TD and bound the public key into its attestation report.

```rust
// client — after verifying the quote and that REPORTDATA == SHA-512(ctx || pk)
let api_key = apikeyenvelope::random_api_key();
let metadata = Metadata::with_expiry("prod/ingest-api", Some(SystemTime::now() + Duration::from_secs(86400)))?;
let envelope = apikeyenvelope::seal(&enclave_public_key, &api_key, &metadata)?;

// enclave
let mut opened = apikeyenvelope::open(&enclave_secret_key, &envelope, SystemTime::now())?;
use_it(opened.api_key_str());
opened.wipe();
```

Ciphersuite: **DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305**
(0x0020 / 0x0001 / 0x0003), HPKE **base mode**, single-shot. AES-128-GCM and
AES-256-GCM are also available through `hpke::Suite`. The envelope is 124 bytes
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

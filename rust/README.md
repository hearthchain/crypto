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

## Prerequisites

- A recent stable Rust toolchain (edition 2024 needs rustc ≥ 1.85; developed on
  1.96). No C toolchain, no native libraries; cross-compiles cleanly.

## Run

```bash
cargo test                     # RFC 9381 / SLIP-0010 / BIP-39 / EIP-2333 / BIP-350 vectors + cross-parity
cargo run --example hearth-demo    # the sample app with a demo mnemonic

# custom inputs:
cargo run --example hearth-demo -- \
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" aGVsbG8= d29ybGQ=

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
  hex.rs         hex helpers
examples/hearth-demo.rs         the sample app
tests/vectors.rs                official vectors + cross-parity with the other builds
```

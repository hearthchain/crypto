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

# vanity address grinder (see below)
cargo run --release --features vanity --bin hearth-vanity -- --prefix hearth

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
  ed25519.rs     keypair from seed / expanded key / bare scalar, sign/verify,
                 VRF scalar/nonce
  ecvrf.rs       RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI
  bech32m.rs     BIP-350 codec
  address.rs     network-independent account identity; HRP at the string boundary
  keytree.rs     the three role keys from one seed
  x25519.rs      RFC 7748 over raw keys (curve25519-dalek Montgomery ladder)
  hpke.rs        RFC 9180 single-shot seal/open, base mode
  apikeyenvelope.rs  the API-key wire format on top of hpke
  hex.rs         hex helpers
  vanity.rs      address grinder core (feature "vanity"): batched-inversion point
                 walk over fiat-crypto field arithmetic
src/bin/hearth-vanity.rs        the grinder CLI (feature "vanity")
examples/hearth-demo.rs         the sample app
examples/hpke-example.rs        seal an API key to an enclave key
tests/vectors.rs                official vectors + cross-parity with the other builds
tests/hpke_vectors.rs           RFC 9180 A.1/A.2 + envelope round-trip/tamper/expiry
tests/vanity.rs                 grinder arithmetic held against curve25519-dalek
```

## Vanity addresses

`hearth-vanity` searches for a signing key whose address starts with a chosen
string. It is behind the `vanity` feature, which pulls in `fiat-crypto` and the
CPU SHA-256 instructions, so a plain library build is unaffected.

```bash
cargo run --release --features vanity --bin hearth-vanity -- --prefix hearth
```
```
searching for hrth1hearth… on 13 thread(s); ~1.074e9 candidates expected per hit
 found after 69491967 candidates in 13.1s (68.20 M/s overall)
address     : hrth1hearthkcfl46zs56n6nrmhrksr5c7g6zyq0khz
public key  : 9f83b6578e3dbf1f8884bbac190e0911d4408d9819e3d2536ab118c42053aa3f
scalar      : 480b702a3e07f3b34cb56b269b2ee04fedce1d7f4f4648b540432f04340f2207
```

The scalar is the private key: `KeyPair::from_scalar(&scalar)` gives an ordinary
[`KeyPair`](../README.md#signing-keys) that signs for that address.

`--hrp thrth` searches testnet strings, `-t` sets the thread count, `-n` keeps
going for several hits. Patterns use the bech32 alphabet
`qpzry9x8gf2tvdw0s3jn54khce6mua7l`, which has no `b`, `i`, `o` or `1`; the tool
rejects anything else rather than searching forever. Only prefixes are supported
— matching a suffix would mean computing the bech32m checksum for every
candidate, which a prefix search skips entirely.

### How fast, and why

Every candidate needs `SHA-256(compress(A_i))`. Three loops, measured on one
M4-class core (this repo's own benchmarks):

| loop | keys/s/core |
|---|---|
| seed → key → address | 0.12 M |
| scalar walk, `dalek` compress per candidate | 0.49 M |
| scalar walk, batched inversion (`src/vanity.rs`) | 6.7 M |

The first is what the naive approach costs: a fixed-base scalar multiplication
per candidate, because `seed → scalar` runs through SHA-512 and is not
homomorphic. The second walks scalars instead — `a_i = a_{i-1} + 1`, so
`A_i = A_{i-1} + B`, one point addition — which is exactly why
[`KeyPair::from_scalar`](../README.md#signing-keys) exists. The third fixes what
then dominates: compressing a point needs `1/Z`, an inversion costing ~250
squarings. Montgomery's trick batches one inversion across a window of 1024
candidates, so each pays ~3 multiplications instead. `curve25519-dalek` cannot
express that — it exposes neither a field type nor point coordinates — so
`src/vanity.rs` carries a small point layer over
[`fiat-crypto`](https://crates.io/crates/fiat-crypto)'s formally verified field
arithmetic.

On this 13-thread M4-class machine that is **64 M keys/s** in aggregate:

| pattern | expected candidates | at 64 M/s |
|---|---|---|
| 5 chars | 3.4e7 | under a second |
| 6 chars | 1.1e9 | ~17 s |
| 7 chars | 3.4e10 | ~9 min |
| 8 chars | 1.1e12 | ~5 hours |
| 9 chars | 3.5e13 | ~6 days |
| 10 chars | 1.1e15 | ~7 months |

Addresses carry no version byte, so all 32 characters after `hrth1` are free and
a pattern of *n* characters costs `32^n` — no wasted low-entropy first character.

### Two things that keep it honest

**Hits are verified before they are printed.** The fast path only *selects*
candidates; each one is then re-derived through the ordinary library path
(`KeyPair::from_scalar` → `Address::from_public_key`) and dropped unless the
address really matches. A bug in the hand-written arithmetic can therefore cost
hits, but cannot hand you a key that does not control the address.
`tests/vanity.rs` additionally pins the whole walk against `curve25519-dalek`,
point for point.

**Starting scalars come from the OS CSPRNG.** The winner is `start + tries` and
`tries` is printed, so anyone who can guess a worker's start can recompute the
private key from the public address. The `profanity` generator drew its start
from a 32-bit seed, which made every address it ever produced brute-forceable —
the bug behind the 2022 Wintermute loss. `vanity::random_start` reduces 64 bytes
of `OsRng` output mod L, and it is the only supported way to start a search.

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

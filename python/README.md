# hearth-chain — Python implementation

A Python port of the hearth-chain crypto foundation — the same pipeline as the other
implementations, byte-for-byte compatible. See the [root README](../README.md) for the
language-independent cryptographic design (schemes, key derivation, addresses, replay
protection). This one covers Python tooling and layout.

Highlights:

- **Ed25519 / EdDSA (RFC 8032)** signatures — Ledger-native.
- **ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381)** for miner election.
- **BLS12-381** key derivation (EIP-2333 / EIP-2334) for finality keys.
- **BIP-39** mnemonics → **SLIP-0010** (ed25519) hierarchical derivation.
- Signing / VRF / BLS keys derived at **separate paths** from one mnemonic.
- **HPKE (RFC 9180)** (`hpke`, `apikeyenvelope`) for sealing a secret to a
  published public key — see [Sealing a secret to a public key](#sealing-a-secret-to-a-public-key).

Curve, hashing and VRF group arithmetic run on **libsodium** (via PyNaCl); the HMAC-based
constructions (PBKDF2, SLIP-0010, HKDF) use the standard library. HPKE's X25519 and AEADs run
on the `cryptography` package instead (see below) rather than through PyNaCl.

## Tooling

- [`uv`](https://docs.astral.sh/uv/) for env & dependencies, `ruff` for lint/format,
  `pytest` for tests, `mypy` for types.

```bash
uv sync                 # create the venv and install deps
uv run hearth-demo      # run the sample app
uv run pytest -q        # run the test vectors (RFC 9381 / 9180 / SLIP-0010 / BIP-39 / EIP-2333 / BIP-350)
uv run ruff check .     # lint
uv run mypy             # type-check

# HPKE example: seal an API key to an enclave's public key, open it, try to forge it
uv run hearth-hpke-example
```

## The sample app (`hearth.demo`)

Given a BIP-39 mnemonic it derives distinct signing / VRF / BLS keys, signs a base64 message
with the signing key, verifies it, then VRF-proves a base64 `alpha` with the VRF key and
derives + verifies the VRF value `beta`.

```bash
uv run hearth-demo                                  # demo mnemonic + sample payloads
uv run hearth-demo "<mnemonic>" <messageB64> <alphaB64>
```

## Layout

```
src/hearth/
  sodium.py           libsodium (PyNaCl) wrapper — hashing + ed25519 group/scalar ops
  bip39.py            mnemonic validation + PBKDF2 seed
  slip10.py           SLIP-0010 ed25519 hierarchical derivation
  bls.py              BLS12-381 key derivation (EIP-2333 / EIP-2334)
  ed25519.py          keypair, sign/verify, VRF scalar/nonce
  ecvrf.py            RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI
  bech32m.py          BIP-350 codec
  address.py          account addresses + Network
  keytree.py          the three role keys from one seed
  x25519.py           RFC 7748 over raw keys (`cryptography`'s X25519)
  hpke.py             RFC 9180 single-shot seal/open, base mode
  apikeyenvelope.py   the API-key wire format on top of hpke
  demo.py             the sample app
  hpke_example.py     seal an API key to an enclave key
tests/                official test vectors + cross-parity with the other builds
  test_hpke.py         RFC 9180 A.1/A.2 vectors + HPKE round-trip/tamper coverage
  test_apikeyenvelope.py  envelope round-trip / tamper / expiry
```

## Sealing a secret to a public key

`apikeyenvelope` covers the case this library was extended for: shipping a
32-character API key to a confidential VM (Intel TDX) that generated an X25519
keypair inside the TD and bound the public key into its attestation report.

```python
# client — after verifying the quote and that REPORTDATA == SHA-512(ctx || pk)
api_key = apikeyenvelope.random_api_key()
envelope = apikeyenvelope.seal(
    enclave_public_key, api_key,
    apikeyenvelope.Metadata("prod/ingest-api", datetime.now(UTC) + timedelta(days=1)),
)

# enclave
opened = apikeyenvelope.open_(enclave_secret_key, envelope)
use(opened.api_key)
opened.wipe()
```

Ciphersuite: **DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305**
(0x0020 / 0x0001 / 0x0003), HPKE **base mode**, single-shot. AES-128-GCM and
AES-256-GCM are also available through `hpke.Suite`. The envelope is 124 bytes
for a 15-character key id, byte-for-byte identical to the Java port's.

X25519 and all three AEADs run on the `cryptography` package rather than
PyNaCl: PyNaCl's own AES-GCM is AES-256-only and gated on
`crypto_aead_aes256gcm_is_available()` (AES-NI), so `cryptography` gives this
module one dependency that is always available instead of mixing PyNaCl's
AEAD with something else for AES-128. HMAC-SHA256 for HKDF still goes through
the standard library, like the rest of this package's HMAC-based
constructions.

**This is only half of the problem.** HPKE gets the key to whoever holds the
private key; it says nothing about *who that is*. The client must verify the
TDX quote — signature chain to Intel's PCS, TCB status, `MRTD`/`RTMR`
measurements — and check that the public key it is about to seal to is the one
hashed into `REPORTDATA`, before calling `seal`. Base mode also leaves the
sender unauthenticated and the ciphertext replayable for as long as the
recipient's private key lives: authorize delivery at the transport layer,
keep the TD's keypair ephemeral per boot, and set an expiry.

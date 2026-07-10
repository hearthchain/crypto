# hearth-chain — Python implementation

A Python port of the hearth-chain crypto foundation — the same pipeline as the Scala
implementation, byte-for-byte compatible. See the [root README](../README.md) for the
language-independent cryptographic design (schemes, key derivation, addresses, replay
protection). This one covers Python tooling and layout.

Highlights:

- **Ed25519 / EdDSA (RFC 8032)** signatures — Ledger-native.
- **ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381)** for miner election.
- **BLS12-381** key derivation (EIP-2333 / EIP-2334) for finality keys.
- **BIP-39** mnemonics → **SLIP-0010** (ed25519) hierarchical derivation.
- Signing / VRF / BLS keys derived at **separate paths** from one mnemonic.

Curve, hashing and VRF group arithmetic run on **libsodium** (via PyNaCl); the HMAC-based
constructions (PBKDF2, SLIP-0010, HKDF) use the standard library.

## Tooling

- [`uv`](https://docs.astral.sh/uv/) for env & dependencies, `ruff` for lint/format,
  `pytest` for tests, `mypy` for types.

```bash
uv sync                 # create the venv and install deps
uv run hearth-demo      # run the sample app
uv run pytest -q        # run the test vectors (RFC 9381 / SLIP-0010 / BIP-39 / EIP-2333 / BIP-350)
uv run ruff check .     # lint
uv run mypy             # type-check
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
  sodium.py    libsodium (PyNaCl) wrapper — hashing + ed25519 group/scalar ops
  bip39.py     mnemonic validation + PBKDF2 seed
  slip10.py    SLIP-0010 ed25519 hierarchical derivation
  bls.py       BLS12-381 key derivation (EIP-2333 / EIP-2334)
  ed25519.py   keypair, sign/verify, VRF scalar/nonce
  ecvrf.py     RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI
  bech32m.py   BIP-350 codec
  address.py   account addresses + Network
  keytree.py   the three role keys from one seed
  demo.py      the sample app
tests/         official test vectors + cross-parity with the Scala build
```

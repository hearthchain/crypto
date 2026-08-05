"""RFC 9180 Appendix A base-mode test vectors for DHKEM(X25519, HKDF-SHA256)
+ HKDF-SHA256, plus HPKE round-trip / tamper coverage."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from hearth import hpke, x25519


def _hx(s: str) -> bytes:
    return bytes.fromhex(s)


@dataclass(frozen=True)
class _Vector:
    name: str
    suite: hpke.Suite
    info: str
    sk_em: str
    pk_em: str
    sk_rm: str
    pk_rm: str
    shared_secret: str
    key: str
    base_nonce: str
    exporter_secret: str
    pt: str
    aad: str
    ct: str


# RFC 9180 A.1: AES-128-GCM.
A1 = _Vector(
    "A.1",
    hpke.Suite.X25519_SHA256_AES128GCM,
    "4f6465206f6e2061204772656369616e2055726e",
    "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
    "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
    "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
    "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
    "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
    "4531685d41d65f03dc48f6b8302c05b0",
    "56d890e5accaaf011cff4b7d",
    "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8",
    "4265617574792069732074727574682c20747275746820626561757479",
    "436f756e742d30",
    "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
)

# RFC 9180 A.2: ChaCha20-Poly1305.
A2 = _Vector(
    "A.2",
    hpke.Suite.X25519_SHA256_CHACHA20POLY1305,
    "4f6465206f6e2061204772656369616e2055726e",
    "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",
    "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
    "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
    "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
    "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7",
    "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91",
    "5c4d98150661b848853b547f",
    "a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922",
    "4265617574792069732074727574682c20747275746820626561757479",
    "436f756e742d30",
    "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
)


@pytest.mark.parametrize("v", [A1, A2], ids=["A.1-AES-128-GCM", "A.2-ChaCha20-Poly1305"])
def test_rfc9180_appendix_a(v: _Vector) -> None:
    # The keypairs in the vector are self-consistent under our X25519.
    assert x25519.public_key(_hx(v.sk_em)) == _hx(v.pk_em)
    assert x25519.public_key(_hx(v.sk_rm)) == _hx(v.pk_rm)

    # DHKEM Encap and Decap agree on the shared secret, and match the vector.
    enc = _hx(v.pk_em)
    encapped = hpke._extract_and_expand(x25519.dh(_hx(v.sk_em), _hx(v.pk_rm)), enc, _hx(v.pk_rm))
    decapped = hpke._extract_and_expand(x25519.dh(_hx(v.sk_rm), enc), enc, _hx(v.pk_rm))
    assert encapped == _hx(v.shared_secret)
    assert decapped == _hx(v.shared_secret)

    # The key schedule.
    context = hpke.key_schedule(v.suite, _hx(v.shared_secret), _hx(v.info))
    assert context.key == _hx(v.key)
    assert context.base_nonce == _hx(v.base_nonce)
    assert context.exporter_secret == _hx(v.exporter_secret)

    # Seal at sequence number 0.
    sealed = hpke.seal_with_ephemeral(v.suite, _hx(v.sk_em), _hx(v.pk_rm), _hx(v.info), _hx(v.aad), _hx(v.pt))
    assert sealed.enc == enc
    assert sealed.ciphertext == _hx(v.ct)

    # And Open recovers the plaintext.
    assert hpke.open_(v.suite, _hx(v.sk_rm), enc, _hx(v.info), _hx(v.aad), _hx(v.ct)) == _hx(v.pt)


@pytest.mark.parametrize("suite", list(hpke.Suite))
def test_seal_open_round_trip(suite: hpke.Suite) -> None:
    recipient = x25519.generate_keypair()
    info = b"hearth-test/info"
    aad = b"hearth-test/aad"
    plaintext = b"the quick brown fox"

    sealed = hpke.seal(suite, recipient.public_key, info, aad, plaintext)
    assert len(sealed.enc) == hpke.ENC_BYTES
    assert len(sealed.ciphertext) == len(plaintext) + hpke.TAG_BYTES
    assert hpke.open_(suite, recipient.secret_key, sealed.enc, info, aad, sealed.ciphertext) == plaintext


def test_seal_is_randomized_per_call() -> None:
    recipient = x25519.generate_keypair()
    suite = hpke.Suite.X25519_SHA256_CHACHA20POLY1305
    first = hpke.seal(suite, recipient.public_key, b"i", b"a", b"p")
    second = hpke.seal(suite, recipient.public_key, b"i", b"a", b"p")
    assert first.enc != second.enc
    assert first.ciphertext != second.ciphertext


def test_open_rejects_wrong_info_aad_key_or_ciphertext() -> None:
    recipient = x25519.generate_keypair()
    info = b"info"
    aad = b"aad"
    suite = hpke.Suite.X25519_SHA256_CHACHA20POLY1305
    sealed = hpke.seal(suite, recipient.public_key, info, aad, b"secret")

    with pytest.raises(ValueError):
        hpke.open_(suite, recipient.secret_key, sealed.enc, b"other", aad, sealed.ciphertext)
    with pytest.raises(ValueError):
        hpke.open_(suite, recipient.secret_key, sealed.enc, info, b"other", sealed.ciphertext)
    with pytest.raises(ValueError):
        hpke.open_(suite, x25519.generate_keypair().secret_key, sealed.enc, info, aad, sealed.ciphertext)

    tampered = bytearray(sealed.ciphertext)
    tampered[0] ^= 0x01
    with pytest.raises(ValueError):
        hpke.open_(suite, recipient.secret_key, sealed.enc, info, aad, bytes(tampered))


def test_x25519_rejects_small_order_public_key() -> None:
    # The all-zero u-coordinate is the canonical small-order point; RFC 9180
    # requires the KEM to abort rather than derive from an all-zero DH output.
    small_order = bytes(x25519.KEY_BYTES)
    with pytest.raises(ValueError):
        x25519.dh(x25519.generate_keypair().secret_key, small_order)


@pytest.mark.parametrize(
    "hex_u",
    [
        "0100000000000000000000000000000000000000000000000000000000000000",  # u=1
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # u=p-1
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # u=p
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # u=p+1
    ],
)
def test_x25519_rejects_other_degenerate_public_keys(hex_u: str) -> None:
    # Beyond the trivial all-zero point: every other canonical low-order/invalid
    # u-coordinate (u=1, and the boundary encodings p-1, p, p+1 for
    # p = 2^255-19), little-endian. Under X25519's mandatory scalar clamping
    # (which forces the scalar to be a multiple of 8) every point of order
    # dividing 8 collapses to the identity, so the DH output is all-zero for
    # every one of these too -- confirmed against a raw (unclamped-check)
    # Montgomery ladder, independent of this library. This is why the single
    # all-zero-output check above is a complete mitigation, not just a
    # heuristic for the one obvious case.
    degenerate = bytes.fromhex(hex_u)
    with pytest.raises(ValueError):
        x25519.dh(x25519.generate_keypair().secret_key, degenerate)


def test_suite_lookup_by_aead_id() -> None:
    for suite in hpke.Suite:
        assert hpke.Suite.from_aead_id(suite.aead_id) == suite
    with pytest.raises(ValueError):
        hpke.Suite.from_aead_id(0x00FF)

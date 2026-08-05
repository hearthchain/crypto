"""Envelope round-trip / tamper / expiry coverage for hearth.apikeyenvelope."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from hearth import apikeyenvelope, hpke, x25519

NOW = datetime(2026, 8, 5, 12, 0, 0, tzinfo=UTC)
LATER = NOW + timedelta(hours=1)


def _meta() -> apikeyenvelope.Metadata:
    return apikeyenvelope.Metadata("prod/ingest-api", LATER)


def _open(recipient: x25519.Keypair, envelope: bytes) -> apikeyenvelope.Opened:
    return apikeyenvelope.open_(recipient.secret_key, envelope, NOW)


@pytest.mark.parametrize("suite", list(hpke.Suite))
def test_seal_open_round_trip(suite: hpke.Suite) -> None:
    recipient = x25519.generate_keypair()
    api_key = apikeyenvelope.random_api_key()

    envelope = apikeyenvelope.seal(recipient.public_key, api_key, _meta(), suite)

    # 20-byte fixed header + metadata + 32-byte enc + 32-byte key + 16-byte tag.
    metadata_length = 1 + len("prod/ingest-api") + 8
    assert len(envelope) == 20 + metadata_length + 32 + 48

    opened = _open(recipient, envelope)
    assert opened.api_key.decode("ascii") == api_key
    assert opened.metadata.key_id == "prod/ingest-api"
    assert opened.metadata.not_after == LATER

    opened.wipe()
    assert opened.api_key == bytearray(apikeyenvelope.API_KEY_LENGTH)


def test_header_carries_the_suite_and_recipient_fingerprint() -> None:
    recipient = x25519.generate_keypair()
    envelope = apikeyenvelope.seal(recipient.public_key, apikeyenvelope.random_api_key(), _meta())

    assert envelope[:4] == b"HKE1"
    assert int.from_bytes(envelope[4:6], "big") == hpke.KEM_ID
    assert int.from_bytes(envelope[6:8], "big") == hpke.KDF_ID
    assert int.from_bytes(envelope[8:10], "big") == apikeyenvelope.DEFAULT_SUITE.aead_id
    assert envelope[10:18] == apikeyenvelope.fingerprint(recipient.public_key)


def test_rejects_envelope_for_another_recipient() -> None:
    recipient = x25519.generate_keypair()
    other = x25519.generate_keypair()
    envelope = apikeyenvelope.seal(recipient.public_key, apikeyenvelope.random_api_key(), _meta())

    with pytest.raises(ValueError, match="different recipient key"):
        _open(other, envelope)


def test_rejects_expired_envelope() -> None:
    recipient = x25519.generate_keypair()
    envelope = apikeyenvelope.seal(
        recipient.public_key,
        apikeyenvelope.random_api_key(),
        apikeyenvelope.Metadata("short-lived", NOW - timedelta(seconds=1)),
    )

    with pytest.raises(ValueError, match="^envelope expired"):
        _open(recipient, envelope)


def test_metadata_without_expiry_never_expires() -> None:
    recipient = x25519.generate_keypair()
    envelope = apikeyenvelope.seal(
        recipient.public_key, apikeyenvelope.random_api_key(), apikeyenvelope.Metadata("forever")
    )

    opened = apikeyenvelope.open_(recipient.secret_key, envelope, datetime(2099, 1, 1, tzinfo=UTC))
    assert opened.metadata.not_after is None


def test_rejects_tampered_metadata() -> None:
    """Every header byte is AAD, so relabelling the metadata breaks the tag."""
    recipient = x25519.generate_keypair()
    envelope = bytearray(
        apikeyenvelope.seal(
            recipient.public_key, apikeyenvelope.random_api_key(), apikeyenvelope.Metadata("prod/ingest-api", LATER)
        )
    )

    # Flip the last byte of the expiry timestamp, still inside the header.
    metadata_end = 20 + 1 + len("prod/ingest-api") + 8
    envelope[metadata_end - 1] ^= 0x01

    with pytest.raises(ValueError, match="not authentic"):
        _open(recipient, bytes(envelope))


def test_rejects_tampered_ciphertext_and_encapsulated_key() -> None:
    recipient = x25519.generate_keypair()
    envelope = apikeyenvelope.seal(recipient.public_key, apikeyenvelope.random_api_key(), _meta())

    for offset in (len(envelope) - 1, len(envelope) - 40, len(envelope) - 60):
        tampered = bytearray(envelope)
        tampered[offset] ^= 0x01
        with pytest.raises(ValueError):
            _open(recipient, bytes(tampered))


def test_rejects_malformed_envelopes() -> None:
    recipient = x25519.generate_keypair()
    envelope = apikeyenvelope.seal(recipient.public_key, apikeyenvelope.random_api_key(), _meta())

    with pytest.raises(ValueError):
        _open(recipient, bytes(3))

    wrong_magic = bytearray(envelope)
    wrong_magic[0] = ord("X")
    with pytest.raises(ValueError):
        _open(recipient, bytes(wrong_magic))

    truncated = envelope[:-1]
    with pytest.raises(ValueError):
        _open(recipient, truncated)

    unknown_aead = bytearray(envelope)
    unknown_aead[9] = 0xFF
    with pytest.raises(ValueError):
        _open(recipient, bytes(unknown_aead))


def test_rejects_api_keys_of_the_wrong_shape() -> None:
    public_key = x25519.generate_keypair().public_key
    with pytest.raises(ValueError):
        apikeyenvelope.seal(public_key, "tooshort", _meta())
    with pytest.raises(ValueError):
        apikeyenvelope.seal(public_key, "0123456789012345678901234567890!", _meta())


def test_metadata_rejects_empty_or_oversized_key_id() -> None:
    with pytest.raises(ValueError):
        apikeyenvelope.Metadata("")
    with pytest.raises(ValueError):
        apikeyenvelope.Metadata("k" * 256)


def test_random_api_key_is_alphanumeric_and_covers_the_alphabet() -> None:
    seen: set[str] = set()
    for _ in range(200):
        key = apikeyenvelope.random_api_key()
        assert len(key) == apikeyenvelope.API_KEY_LENGTH
        for c in key:
            assert c.isalnum() and c.isascii(), f"not ASCII alphanumeric: {c}"
            seen.add(c)
    # 6400 draws over a 62-character alphabet: every character should appear.
    assert len(seen) == 62

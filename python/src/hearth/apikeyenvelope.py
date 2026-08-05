"""The wire format for handing an API key to a recipient that published an
X25519 public key — typically a confidential VM (Intel TDX) that generated
the key inside the TD and bound it into its attestation report.

The envelope is a thin, self-describing frame around :mod:`hearth.hpke`::

    offset size field
    0      4    "HKE1"                      format magic and version
    4      2    kem_id                      0x0020, DHKEM(X25519, HKDF-SHA256)
    6      2    kdf_id                      0x0001, HKDF-SHA256
    8      2    aead_id                     0x0003 by default, ChaCha20-Poly1305
    10     8    fingerprint                 SHA-256(recipient public key)[0..8]
    18     2    metadata_len
    20     m    metadata                    key id and expiry, see Metadata
    20+m   32   enc                         the encapsulated key
    52+m   48   ciphertext                  32-byte API key + 16-byte tag

Everything before ``enc`` is passed to the AEAD as additional authenticated
data, so the suite ids, the recipient fingerprint and the metadata are all
covered by the tag: an envelope cannot be re-labelled with a different key id
or expiry, and the ``info`` string pins it to this protocol so it cannot be
replayed into another one.

The fingerprint is a routing hint, not a security control — the recipient
uses it to reject an envelope sealed to a previous boot's key with a clear
error instead of an authentication failure.

**What this does not give you.** HPKE base mode does not authenticate the
sender, and an envelope stays decryptable as long as the recipient's private
key lives: authorize the delivery request at the transport layer, keep the
recipient keypair ephemeral per boot, and set ``Metadata.not_after``. And none
of it means anything until the caller has verified the attestation quote and
checked that the recipient's public key is the one bound into ``REPORTDATA``.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime

from . import hpke, x25519

# API keys are exactly this many characters.
API_KEY_LENGTH = 32

# ChaCha20-Poly1305: no reliance on the TD having usable AES-NI.
DEFAULT_SUITE = hpke.Suite.X25519_SHA256_CHACHA20POLY1305

# Bytes of SHA-256(public key) carried in the header.
FINGERPRINT_BYTES = 8

# The HPKE info string. Changing it breaks compatibility, by design.
_INFO = b"hearth-chain/api-key-hpke/v1"

_MAGIC = b"HKE1"
_HEADER_FIXED_BYTES = 20
_MAX_METADATA_BYTES = 0xFFFF

_ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
# Largest multiple of 62 that fits in a byte; above it, resample (no modulo bias).
_SAMPLE_LIMIT = (256 // len(_ALPHANUMERIC)) * len(_ALPHANUMERIC)


@dataclass(frozen=True)
class Metadata:
    """What the envelope claims about the key it carries, authenticated by
    the AEAD tag.

    ``key_id`` is an identifier for the API key, 1..255 bytes of UTF-8; it
    lets the recipient tell which key it received without logging the key
    itself. ``not_after`` is when the key stops being valid, or ``None`` for
    no expiry. Truncated to whole seconds on the wire.
    """

    key_id: str
    not_after: datetime | None = None

    def __post_init__(self) -> None:
        length = len(self.key_id.encode("utf-8"))
        if length < 1 or length > 255:
            raise ValueError(f"key id must be 1..255 bytes of UTF-8, was {length}")

    def _encode(self) -> bytes:
        id_bytes = self.key_id.encode("utf-8")
        epoch_seconds = 0 if self.not_after is None else int(self.not_after.timestamp())
        return bytes([len(id_bytes)]) + id_bytes + epoch_seconds.to_bytes(8, "big", signed=True)

    @staticmethod
    def _decode(encoded: bytes) -> Metadata:
        if len(encoded) < 1 + 8:
            raise ValueError("truncated envelope metadata")
        length = encoded[0]
        if len(encoded) != 1 + length + 8:
            raise ValueError("envelope metadata length mismatch")
        key_id = encoded[1 : 1 + length].decode("utf-8")
        epoch_seconds = int.from_bytes(encoded[1 + length :], "big", signed=True)
        not_after = None if epoch_seconds == 0 else datetime.fromtimestamp(epoch_seconds, tz=UTC)
        return Metadata(key_id, not_after)


@dataclass
class Opened:
    """A decrypted envelope. Call :meth:`wipe` once the key has been used —
    the point of returning a ``bytearray`` is that it can be cleared, which a
    ``str`` cannot."""

    api_key: bytearray
    metadata: Metadata

    def wipe(self) -> None:
        for i in range(len(self.api_key)):
            self.api_key[i] = 0


def seal(
    recipient_public_key: bytes,
    api_key: str | bytearray,
    metadata: Metadata,
    suite: hpke.Suite = DEFAULT_SUITE,
) -> bytes:
    """Seal an API key to ``recipient_public_key``.

    The caller must already have verified that this public key belongs to
    the enclave it expects; this function cannot check that.

    Raises ValueError if the API key is not :data:`API_KEY_LENGTH`
    alphanumeric characters.
    """
    key_str = api_key.decode("ascii") if isinstance(api_key, (bytes, bytearray)) else api_key
    _validate_api_key(key_str)
    header = _header(suite, fingerprint(recipient_public_key), metadata._encode())
    plaintext = key_str.encode("ascii")
    sealed = hpke.seal(suite, recipient_public_key, _INFO, header, plaintext)
    return header + sealed.enc + sealed.ciphertext


def open_(recipient_secret_key: bytes, envelope: bytes, now: datetime | None = None) -> Opened:
    """Open an envelope, rejecting one that has expired.

    ``now`` is the instant to judge ``Metadata.not_after`` against (defaults
    to the current time).

    Raises ValueError if the envelope is malformed, sealed to a different
    recipient key, not authentic, or expired.
    """
    if now is None:
        now = datetime.now(UTC)
    if len(envelope) < _HEADER_FIXED_BYTES:
        raise ValueError("truncated envelope")
    if envelope[:4] != _MAGIC:
        raise ValueError("not an API key envelope")

    kem_id = int.from_bytes(envelope[4:6], "big")
    kdf_id = int.from_bytes(envelope[6:8], "big")
    aead_id = int.from_bytes(envelope[8:10], "big")
    if kem_id != hpke.KEM_ID or kdf_id != hpke.KDF_ID:
        raise ValueError(f"unsupported HPKE suite: kem=0x{kem_id:04x} kdf=0x{kdf_id:04x}")
    suite = hpke.Suite.from_aead_id(aead_id)

    env_fingerprint = envelope[10:18]
    metadata_length = int.from_bytes(envelope[18:20], "big")

    ciphertext_length = API_KEY_LENGTH + hpke.TAG_BYTES
    expected = _HEADER_FIXED_BYTES + metadata_length + hpke.ENC_BYTES + ciphertext_length
    if len(envelope) != expected:
        raise ValueError(f"envelope length mismatch: expected {expected} bytes, got {len(envelope)}")

    offset = _HEADER_FIXED_BYTES
    metadata_bytes = envelope[offset : offset + metadata_length]
    offset += metadata_length
    enc = envelope[offset : offset + hpke.ENC_BYTES]
    offset += hpke.ENC_BYTES
    ciphertext = envelope[offset : offset + ciphertext_length]

    recipient_public_key = x25519.public_key(recipient_secret_key)
    if env_fingerprint != fingerprint(recipient_public_key):
        raise ValueError("envelope is sealed to a different recipient key")

    # Everything before enc is the AAD, so the suite ids, fingerprint and
    # metadata are all covered by the tag.
    header = envelope[: _HEADER_FIXED_BYTES + metadata_length]
    plaintext = hpke.open_(suite, recipient_secret_key, enc, _INFO, header, ciphertext)

    api_key = plaintext.decode("ascii")
    _validate_api_key(api_key)
    metadata = Metadata._decode(metadata_bytes)
    if metadata.not_after is not None and now >= metadata.not_after:
        raise ValueError(f"envelope expired at {metadata.not_after}")
    return Opened(bytearray(plaintext), metadata)


def fingerprint(public_key: bytes) -> bytes:
    """SHA-256(public key) truncated to :data:`FINGERPRINT_BYTES` bytes."""
    if len(public_key) != x25519.KEY_BYTES:
        raise ValueError(f"public key must be {x25519.KEY_BYTES} bytes")
    return hashlib.sha256(public_key).digest()[:FINGERPRINT_BYTES]


def random_api_key() -> str:
    """A fresh :data:`API_KEY_LENGTH`-character alphanumeric API key, uniform
    over the 62-character alphabet (rejection sampling — ``% 62`` on a random
    byte would favour the first 8 characters)."""
    chars: list[str] = []
    while len(chars) < API_KEY_LENGTH:
        for b in secrets.token_bytes(API_KEY_LENGTH):
            if len(chars) >= API_KEY_LENGTH:
                break
            if b < _SAMPLE_LIMIT:
                chars.append(_ALPHANUMERIC[b % len(_ALPHANUMERIC)])
    return "".join(chars)


def _header(suite: hpke.Suite, fp: bytes, metadata: bytes) -> bytes:
    if len(metadata) > _MAX_METADATA_BYTES:
        raise ValueError(f"envelope metadata too long: {len(metadata)}")
    return (
        _MAGIC
        + hpke.KEM_ID.to_bytes(2, "big")
        + hpke.KDF_ID.to_bytes(2, "big")
        + suite.aead_id.to_bytes(2, "big")
        + fp
        + len(metadata).to_bytes(2, "big")
        + metadata
    )


def _validate_api_key(api_key: str) -> None:
    if len(api_key) != API_KEY_LENGTH:
        raise ValueError(f"API key must be {API_KEY_LENGTH} characters")
    if not all(c.isalnum() and c.isascii() for c in api_key):
        raise ValueError("API key must be alphanumeric")

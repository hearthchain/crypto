"""HPKE (RFC 9180) single-shot public-key encryption, base mode, over
**DHKEM(X25519, HKDF-SHA256)** + **HKDF-SHA256**.

Base mode means the sender is anonymous: anyone holding the recipient's
public key can seal. That is exactly the shape of "encrypt a secret to a
public key published by an enclave" — the recipient is authenticated (by
attestation, out of band), the sender is authorized by the transport.

Only the single-shot Seal/Open of RFC 9180 SS6.1 is implemented — one message
per encapsulation, always at sequence number 0. There is deliberately no
stateful sender context to reuse, so a nonce can never be repeated under one
key.

The AEADs and the X25519 group operation both run on the ``cryptography``
package; HMAC-SHA256 (for HKDF) runs on the standard library, matching the
rest of this codebase's HMAC-based constructions. Verified against the
RFC 9180 A.1 and A.2 test vectors.

See :mod:`hearth.apikeyenvelope` for the ready-made wire format this library
uses for shipping an API key to an enclave.
"""

from __future__ import annotations

import enum
import hashlib
import hmac as _hmac
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from . import x25519

# DHKEM(X25519, HKDF-SHA256).
KEM_ID = 0x0020

# HKDF-SHA256.
KDF_ID = 0x0001

# Size of an encapsulated key (a serialized X25519 public key).
ENC_BYTES = x25519.KEY_BYTES

# Every AEAD here has a 16-byte tag.
TAG_BYTES = 16

_MODE_BASE = 0x00
_NH = 32  # Nh for HKDF-SHA256
_NSECRET = 32  # Nsecret for DHKEM(X25519, ...)

_HPKE_V1 = b"HPKE-v1"
_KEM_SUITE_ID = b"KEM" + KEM_ID.to_bytes(2, "big")
_EMPTY = b""


class Suite(enum.Enum):
    """The supported ciphersuites. All share DHKEM(X25519, HKDF-SHA256) and
    HKDF-SHA256 and differ only in the AEAD."""

    # RFC 9180 A.1. The mandatory-to-implement AEAD.
    X25519_SHA256_AES128GCM = (0x0001, 16)
    # 256-bit AES, for when a key-size policy asks for it.
    X25519_SHA256_AES256GCM = (0x0002, 32)
    # RFC 9180 A.2. The default here: no AES-NI dependency for constant time.
    X25519_SHA256_CHACHA20POLY1305 = (0x0003, 32)

    def __init__(self, aead_id: int, key_bytes: int) -> None:
        self.aead_id = aead_id
        self.key_bytes = key_bytes

    @property
    def nonce_bytes(self) -> int:
        """AEAD nonce length, Nn. 12 for every AEAD registered so far."""
        return 12

    @staticmethod
    def from_aead_id(aead_id: int) -> Suite:
        for suite in Suite:
            if suite.aead_id == aead_id:
                return suite
        raise ValueError(f"unsupported HPKE AEAD id: 0x{aead_id:04x}")


@dataclass(frozen=True)
class Sealed:
    """The output of Seal: the encapsulated key and the ciphertext."""

    enc: bytes
    ciphertext: bytes


@dataclass(frozen=True)
class Context:
    """The key schedule outputs of RFC 9180 SS5.1."""

    key: bytes
    base_nonce: bytes
    exporter_secret: bytes


def seal(suite: Suite, recipient_public_key: bytes, info: bytes, aad: bytes, plaintext: bytes) -> Sealed:
    """Encrypt ``plaintext`` to ``recipient_public_key``.

    ``info`` is application context bound into the key schedule; it must be a
    fixed, purpose-specific string so ciphertexts cannot be replayed into a
    different protocol. ``aad`` is additional authenticated data,
    authenticated but not encrypted.
    """
    ephemeral = x25519.generate_keypair()
    return seal_with_ephemeral(suite, ephemeral.secret_key, recipient_public_key, info, aad, plaintext)


def open_(
    suite: Suite,
    recipient_secret_key: bytes,
    enc: bytes,
    info: bytes,
    aad: bytes,
    ciphertext: bytes,
) -> bytes:
    """Decrypt.

    Raises ValueError if authentication fails — a corrupt, forged, or
    mis-addressed ciphertext is indistinguishable here.
    """
    if len(enc) != ENC_BYTES:
        raise ValueError(f"enc must be {ENC_BYTES} bytes")
    if len(ciphertext) < TAG_BYTES:
        raise ValueError("ciphertext is shorter than the AEAD tag")
    dh = x25519.dh(recipient_secret_key, enc)
    recipient_public_key = x25519.public_key(recipient_secret_key)
    shared_secret = _extract_and_expand(dh, enc, recipient_public_key)
    context = key_schedule(suite, shared_secret, info)
    return _aead_open(suite, context.key, context.base_nonce, aad, ciphertext)


# ---------------------------------------------------------------- internals


def seal_with_ephemeral(
    suite: Suite,
    ephemeral_secret_key: bytes,
    recipient_public_key: bytes,
    info: bytes,
    aad: bytes,
    plaintext: bytes,
) -> Sealed:
    """Seal with a caller-supplied ephemeral key.

    Exposed (as in the Java port) for the RFC 9180 vectors, which pin
    ``skEm``; outside a test a reused ephemeral key would repeat the AEAD
    nonce, so ordinary callers should use :func:`seal` instead.
    """
    if len(recipient_public_key) != x25519.KEY_BYTES:
        raise ValueError(f"recipient public key must be {x25519.KEY_BYTES} bytes")
    enc = x25519.public_key(ephemeral_secret_key)
    dh = x25519.dh(ephemeral_secret_key, recipient_public_key)
    shared_secret = _extract_and_expand(dh, enc, recipient_public_key)
    context = key_schedule(suite, shared_secret, info)
    ciphertext = _aead_seal(suite, context.key, context.base_nonce, aad, plaintext)
    return Sealed(enc, ciphertext)


def _extract_and_expand(dh: bytes, enc: bytes, recipient_public_key: bytes) -> bytes:
    """DHKEM's ExtractAndExpand (RFC 9180 SS4.1), shared by Encap and Decap."""
    kem_context = enc + recipient_public_key
    eae_prk = _labeled_extract(_KEM_SUITE_ID, _EMPTY, "eae_prk", dh)
    return _labeled_expand(_KEM_SUITE_ID, eae_prk, "shared_secret", kem_context, _NSECRET)


def key_schedule(suite: Suite, shared_secret: bytes, info: bytes) -> Context:
    """KeySchedule for mode_base (RFC 9180 SS5.1): psk and psk_id are empty."""
    suite_id = _suite_id(suite)
    psk_id_hash = _labeled_extract(suite_id, _EMPTY, "psk_id_hash", _EMPTY)
    info_hash = _labeled_extract(suite_id, _EMPTY, "info_hash", info)
    key_schedule_context = bytes([_MODE_BASE]) + psk_id_hash + info_hash

    secret = _labeled_extract(suite_id, shared_secret, "secret", _EMPTY)
    return Context(
        _labeled_expand(suite_id, secret, "key", key_schedule_context, suite.key_bytes),
        _labeled_expand(suite_id, secret, "base_nonce", key_schedule_context, suite.nonce_bytes),
        _labeled_expand(suite_id, secret, "exp", key_schedule_context, _NH),
    )


def _suite_id(suite: Suite) -> bytes:
    return b"HPKE" + KEM_ID.to_bytes(2, "big") + KDF_ID.to_bytes(2, "big") + suite.aead_id.to_bytes(2, "big")


def _labeled_extract(suite_id: bytes, salt: bytes, label: str, ikm: bytes) -> bytes:
    return _extract(salt, _HPKE_V1 + suite_id + label.encode("ascii") + ikm)


def _labeled_expand(suite_id: bytes, prk: bytes, label: str, info: bytes, length: int) -> bytes:
    frame = length.to_bytes(2, "big") + _HPKE_V1 + suite_id + label.encode("ascii") + info
    return _expand(prk, frame, length)


def _extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract (RFC 5869 SS2.2). An empty salt becomes HashLen zero
    bytes, as the RFC specifies."""
    return _hmac.new(salt if len(salt) > 0 else bytes(_NH), ikm, hashlib.sha256).digest()


def _expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand (RFC 5869 SS2.3)."""
    if length < 0 or length > 255 * _NH:
        raise ValueError(f"HKDF-Expand length out of range: {length}")
    out = bytearray()
    block = _EMPTY
    counter = 1
    while len(out) < length:
        block = _hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def _aead_seal(suite: Suite, key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    result: bytes = _aead(suite, key).encrypt(nonce, plaintext, aad if len(aad) > 0 else None)
    return result


def _aead_open(suite: Suite, key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    try:
        result: bytes = _aead(suite, key).decrypt(nonce, ciphertext, aad if len(aad) > 0 else None)
        return result
    except Exception as exc:  # cryptography raises InvalidTag
        raise ValueError("HPKE open failed: ciphertext is not authentic") from exc


def _aead(suite: Suite, key: bytes) -> AESGCM | ChaCha20Poly1305:
    if suite == Suite.X25519_SHA256_CHACHA20POLY1305:
        return ChaCha20Poly1305(key)
    return AESGCM(key)

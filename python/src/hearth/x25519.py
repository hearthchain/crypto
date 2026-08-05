"""X25519 (RFC 7748) over raw 32-byte little-endian keys — the Diffie-Hellman
half of :mod:`hearth.hpke`'s DHKEM.

Runs on the ``cryptography`` package's X25519 (OpenSSL under the hood)
rather than PyNaCl/libsodium: it is the same foundation :mod:`hearth.hpke`
uses for its AEADs, so the whole HPKE module has one dependency instead of
mixing PyNaCl's hardware-gated AES-GCM with something else. Keys are handled
in the wire encoding RFC 7748 and RFC 9180 use: 32 bytes, little-endian,
unclamped (X25519 clamps the scalar internally).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

KEY_BYTES = 32


@dataclass(frozen=True)
class Keypair:
    public_key: bytes
    secret_key: bytes


def generate_keypair() -> Keypair:
    """A fresh keypair. The secret is 32 uniformly random bytes; X25519 clamps
    them when they are used, so every draw is a valid scalar."""
    sk = os.urandom(KEY_BYTES)
    return Keypair(public_key(sk), sk)


def public_key(secret_key: bytes) -> bytes:
    """The public key for a secret scalar, i.e. X25519(sk, 9)."""
    _check_len(secret_key, "secret")
    priv = X25519PrivateKey.from_private_bytes(secret_key)
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def dh(secret_key: bytes, public_key_bytes: bytes) -> bytes:
    """The Diffie-Hellman shared coordinate X25519(sk, pk).

    Raises ValueError if ``public_key_bytes`` has small order (an all-zero
    result), which RFC 9180 SS7.1.4 requires KEMs to reject.
    """
    _check_len(secret_key, "secret")
    _check_len(public_key_bytes, "public")
    priv = X25519PrivateKey.from_private_bytes(secret_key)
    pub = X25519PublicKey.from_public_bytes(public_key_bytes)
    shared = priv.exchange(pub)
    if _is_all_zero(shared):
        raise ValueError("X25519: public key has small order")
    return shared


def _is_all_zero(value: bytes) -> bool:
    acc = 0
    for b in value:
        acc |= b
    return acc == 0


def _check_len(value: bytes, name: str) -> None:
    if len(value) != KEY_BYTES:
        raise ValueError(f"X25519 {name} key must be {KEY_BYTES} bytes")

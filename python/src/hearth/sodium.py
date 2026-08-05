"""Thin wrapper over libsodium (via PyNaCl's low-level ``nacl.bindings``).

Only hashing and ed25519 group/scalar arithmetic go through libsodium here; the
HMAC-based constructions (PBKDF2, SLIP-0010, HKDF) use the standard library in
their own modules. Point/scalar functions that libsodium can reject return
``None`` instead of raising, mirroring an ``Option``-style result.
"""

from __future__ import annotations

import nacl.bindings as _sodium
from nacl.exceptions import RuntimeError as _SodiumError

POINT_BYTES = 32
SCALAR_BYTES = 32
SIGN_BYTES = 64


def sha512(data: bytes) -> bytes:
    return _sodium.crypto_hash_sha512(data)


def sha256(data: bytes) -> bytes:
    return _sodium.crypto_hash_sha256(data)


def sign_seed_keypair(seed: bytes) -> tuple[bytes, bytes]:
    """Return (public_key[32], secret_key[64] = seed||public_key)."""
    return _sodium.crypto_sign_seed_keypair(seed)


def sign_detached(message: bytes, secret_key: bytes) -> bytes:
    # libsodium crypto_sign outputs signature(64) || message; take the prefix.
    return _sodium.crypto_sign(message, secret_key)[:SIGN_BYTES]


def verify_detached(signature: bytes, message: bytes, public_key: bytes) -> bool:
    try:
        _sodium.crypto_sign_open(signature + message, public_key)
        return True
    except Exception:  # noqa: BLE001 - any verification failure means "invalid"
        return False


def point_add(p: bytes, q: bytes) -> bytes | None:
    """Ed25519 point addition; on-curve check only (what RFC 9381 TAI needs)."""
    try:
        return _sodium.crypto_core_ed25519_add(p, q)
    except _SodiumError:
        return None


def point_sub(p: bytes, q: bytes) -> bytes | None:
    try:
        return _sodium.crypto_core_ed25519_sub(p, q)
    except _SodiumError:
        return None


def scalarmult_noclamp(n: bytes, p: bytes) -> bytes | None:
    """q = n*p, scalar used verbatim. Requires p on the prime-order subgroup."""
    try:
        return _sodium.crypto_scalarmult_ed25519_noclamp(n, p)
    except _SodiumError:
        return None


def scalarmult_base_noclamp(n: bytes) -> bytes:
    return _sodium.crypto_scalarmult_ed25519_base_noclamp(n)


def scalar_mul(x: bytes, y: bytes) -> bytes:
    return _sodium.crypto_core_ed25519_scalar_mul(x, y)


def scalar_add(x: bytes, y: bytes) -> bytes:
    return _sodium.crypto_core_ed25519_scalar_add(x, y)


def scalar_reduce(wide: bytes) -> bytes:
    """Reduce a 64-byte little-endian value mod L to a 32-byte scalar."""
    return _sodium.crypto_core_ed25519_scalar_reduce(wide)

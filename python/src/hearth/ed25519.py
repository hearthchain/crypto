"""Ed25519 (EdDSA, RFC 8032) keys and signatures. The same key backs the ECVRF."""

from __future__ import annotations

from dataclasses import dataclass

from . import sodium


@dataclass(frozen=True)
class KeyPair:
    seed: bytes  # 32-byte SLIP-0010 node key (the RFC 9381 "SK")
    public_key: bytes
    secret_key: bytes  # libsodium's 64-byte expanded form (seed || public_key)

    def sign(self, message: bytes) -> bytes:
        return sodium.sign_detached(message, self.secret_key)


def from_seed(seed: bytes) -> KeyPair:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    public_key, secret_key = sodium.sign_seed_keypair(seed)
    return KeyPair(seed, public_key, secret_key)


def verify(signature: bytes, message: bytes, public_key: bytes) -> bool:
    return sodium.verify_detached(signature, message, public_key)


def secret_scalar(seed: bytes) -> bytes:
    """RFC 8032 secret scalar: clamp(SHA-512(seed)[0:32]). Used by ECVRF."""
    a = bytearray(sodium.sha512(seed)[:32])
    a[0] &= 0xF8
    a[31] = (a[31] & 0x7F) | 0x40
    return bytes(a)


def nonce_prefix(seed: bytes) -> bytes:
    """RFC 8032 nonce prefix: SHA-512(seed)[32:64]. Used by ECVRF nonce gen."""
    return sodium.sha512(seed)[32:64]

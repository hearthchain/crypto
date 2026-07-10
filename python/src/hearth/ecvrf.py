"""ECVRF-EDWARDS25519-SHA512-TAI, the RFC 9381 VRF (suite_string = 0x03).

Reuses the exact Ed25519 key: the VRF secret scalar is ``clamp(SHA-512(seed))``
and the VRF public key is the Ed25519 public key. Curve/scalar arithmetic runs on
libsodium via :mod:`hearth.sodium`.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import ed25519, sodium

_SUITE = b"\x03"
_PT_LEN = sodium.POINT_BYTES  # 32
_C_LEN = 16
_PROOF_LEN = _PT_LEN + _C_LEN + _PT_LEN  # 80
_IDENTITY = b"\x01" + b"\x00" * 31


@dataclass(frozen=True)
class Proof:
    gamma: bytes
    c: bytes
    s: bytes

    @property
    def bytes(self) -> bytes:
        return self.gamma + self.c + self.s


def prove(seed: bytes, alpha: bytes) -> tuple[Proof, bytes]:
    """Return (proof pi, VRF output beta[64])."""
    x = ed25519.secret_scalar(seed)
    y = sodium.scalarmult_base_noclamp(x)  # public key Y = x*B
    h = _encode_to_curve(y, alpha)
    gamma = _require(sodium.scalarmult_noclamp(x, h), "Gamma = x*H failed")
    k = _nonce(seed, h)
    u = sodium.scalarmult_base_noclamp(k)  # U = k*B
    v = _require(sodium.scalarmult_noclamp(k, h), "V = k*H failed")  # V = k*H
    c = _challenge(y, h, gamma, u, v)  # 16 bytes
    c32 = c + b"\x00" * (_PT_LEN - _C_LEN)
    s = sodium.scalar_add(k, sodium.scalar_mul(c32, x))  # s = k + c*x mod L
    proof = Proof(gamma, c, s)
    return proof, proof_to_hash(proof)


def verify(public_key: bytes, alpha: bytes, pi: bytes) -> bytes | None:
    """Return beta if the proof is valid, else ``None``."""
    proof = decode(pi)
    if proof is None:
        return None
    h = _encode_to_curve(public_key, alpha)
    c32 = proof.c + b"\x00" * (_PT_LEN - _C_LEN)
    s_b = sodium.scalarmult_base_noclamp(proof.s)
    c_y = sodium.scalarmult_noclamp(c32, public_key)
    if c_y is None:
        return None
    u = sodium.point_sub(s_b, c_y)  # U = s*B - c*Y
    s_h = sodium.scalarmult_noclamp(proof.s, h)
    c_gamma = sodium.scalarmult_noclamp(c32, proof.gamma)
    if u is None or s_h is None or c_gamma is None:
        return None
    v = sodium.point_sub(s_h, c_gamma)  # V = s*H - c*Gamma
    if v is None:
        return None
    if _challenge(public_key, h, proof.gamma, u, v) != proof.c:
        return None
    return proof_to_hash(proof)


def proof_to_hash(proof: Proof) -> bytes:
    """beta = SHA-512(suite || 0x03 || point_to_string(8*Gamma) || 0x00)."""
    gamma8 = _require(_cofactor_clear(proof.gamma), "8*Gamma failed")
    return sodium.sha512(_SUITE + b"\x03" + gamma8 + b"\x00")


def decode(pi: bytes) -> Proof | None:
    if len(pi) != _PROOF_LEN:
        return None
    return Proof(pi[:_PT_LEN], pi[_PT_LEN : _PT_LEN + _C_LEN], pi[_PT_LEN + _C_LEN :])


# --- internals -----------------------------------------------------------


def _encode_to_curve(pk_string: bytes, alpha: bytes) -> bytes:
    """ECVRF_encode_to_curve_try_and_increment (RFC 9381 5.4.1.1)."""
    for ctr in range(256):
        hash_string = sodium.sha512(_SUITE + b"\x01" + pk_string + alpha + bytes([ctr]) + b"\x00")
        candidate = hash_string[:_PT_LEN]  # string_to_point(first 32 bytes)
        cleared = _cofactor_clear(candidate)  # None => off-curve => next ctr
        if cleared is not None and cleared != _IDENTITY:
            return cleared
    raise RuntimeError("encode_to_curve: no valid point found")


def _cofactor_clear(p: bytes) -> bytes | None:
    """Multiply a compressed point by cofactor 8 via three doublings (on-curve
    check only). Returns None if the input does not decode to a curve point."""
    p2 = sodium.point_add(p, p)
    if p2 is None:
        return None
    p4 = sodium.point_add(p2, p2)
    if p4 is None:
        return None
    return sodium.point_add(p4, p4)


def _nonce(seed: bytes, h_string: bytes) -> bytes:
    """ECVRF_nonce_generation_RFC8032 (RFC 9381 5.4.2.2)."""
    k_string = sodium.sha512(ed25519.nonce_prefix(seed) + h_string)
    return sodium.scalar_reduce(k_string)  # k = string_to_int(k_string) mod L


def _challenge(y: bytes, h: bytes, gamma: bytes, u: bytes, v: bytes) -> bytes:
    """ECVRF_challenge_generation (RFC 9381 5.4.3): first 16 bytes of the hash."""
    return sodium.sha512(_SUITE + b"\x02" + y + h + gamma + u + v + b"\x00")[:_C_LEN]


def _require(value: bytes | None, message: str) -> bytes:
    if value is None:
        raise RuntimeError(message)
    return value

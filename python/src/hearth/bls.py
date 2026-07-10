"""BLS12-381 key derivation per EIP-2333 (key generation) and EIP-2334 (paths).

Only derivation is implemented — it is pure HKDF-SHA-256 + SHA-256 + ``mod r``
and needs no pairing library. Signing/aggregation/PoP would require a pairing
backend (e.g. ``blst``) and are intentionally omitted.

Unlike SLIP-0010, EIP-2333 has NO hardened/non-hardened distinction: every child
is derived from the parent secret key, so all keys are hardened-equivalent and
paths carry no ``'`` marker.
"""

from __future__ import annotations

import hashlib
import hmac

# BLS12-381 subgroup order r.
R = 52435875175126190479447740508185965837690552500527637822603658699938581184513
# EIP-2334 purpose (the curve id).
PURPOSE = 12381

_KEYGEN_SALT = b"BLS-SIG-KEYGEN-SALT-"
_SHA256_LEN = 32
_LAMPORT_CHUNKS = 255


def derive_master_sk(seed: bytes) -> bytes:
    """Master secret key from a seed (>= 32 bytes). Returns 32-byte big-endian scalar."""
    if len(seed) < 32:
        raise ValueError("EIP-2333 seed must be at least 32 bytes")
    return _hkdf_mod_r(seed)


def derive_child_sk(parent_sk: bytes, index: int) -> bytes:
    """One child derivation step. ``index`` is a uint32 (0 .. 2**32-1)."""
    if not 0 <= index <= 0xFFFFFFFF:
        raise ValueError("index must fit in uint32")
    return _hkdf_mod_r(_parent_sk_to_lamport_pk(parent_sk, index))


def derive_path(seed: bytes, path: str) -> bytes:
    sk = derive_master_sk(seed)
    for index in parse_path(path):
        sk = derive_child_sk(sk, index)
    return sk


def parse_path(path: str) -> list[int]:
    trimmed = path.strip()
    if trimmed != "m" and not trimmed.startswith("m/"):
        raise ValueError(f"path must start with 'm': {path}")
    if trimmed == "m":
        return []
    result: list[int] = []
    for raw in trimmed[2:].split("/"):
        if "'" in raw:
            raise ValueError(f"BLS (EIP-2333) has no hardened notation; drop the ' in '{raw}'")
        n = int(raw)
        if not 0 <= n <= 0xFFFFFFFF:
            raise ValueError(f"index out of uint32 range: {raw}")
        result.append(n)
    return result


# --- EIP-2333 internals --------------------------------------------------


def _hkdf_mod_r(ikm: bytes, key_info: bytes = b"") -> bytes:
    length = 48  # ceil((3 * ceil(log2(r))) / 16)
    salt = _KEYGEN_SALT
    sk = 0
    while sk == 0:
        salt = hashlib.sha256(salt).digest()
        prk = _hkdf_extract(salt, ikm + b"\x00")  # HKDF-Extract(salt, IKM || I2OSP(0,1))
        okm = _hkdf_expand(prk, key_info + length.to_bytes(2, "big"), length)
        sk = int.from_bytes(okm, "big") % R
    return sk.to_bytes(32, "big")


def _parent_sk_to_lamport_pk(parent_sk: bytes, index: int) -> bytes:
    salt = index.to_bytes(4, "big")
    ikm = parent_sk.rjust(32, b"\x00")
    not_ikm = bytes(b ^ 0xFF for b in ikm)
    lamport_0 = _ikm_to_lamport_sk(salt, ikm)
    lamport_1 = _ikm_to_lamport_sk(salt, not_ikm)
    buf = bytearray()
    for chunk in lamport_0:
        buf += hashlib.sha256(chunk).digest()
    for chunk in lamport_1:
        buf += hashlib.sha256(chunk).digest()
    return hashlib.sha256(bytes(buf)).digest()


def _ikm_to_lamport_sk(salt: bytes, ikm: bytes) -> list[bytes]:
    prk = _hkdf_extract(salt, ikm)
    okm = _hkdf_expand(prk, b"", _LAMPORT_CHUNKS * _SHA256_LEN)
    return [okm[i * _SHA256_LEN : (i + 1) * _SHA256_LEN] for i in range(_LAMPORT_CHUNKS)]


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, "sha256").digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    if length > 255 * _SHA256_LEN:
        raise ValueError("HKDF-Expand length exceeds 255*HashLen")
    out = bytearray()
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), "sha256").digest()
        out += t
        counter += 1
    return bytes(out[:length])

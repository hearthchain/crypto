"""SLIP-0010 hierarchical key derivation for the ed25519 curve (hardened-only)."""

from __future__ import annotations

import hmac
from dataclasses import dataclass

_ED25519_MASTER_KEY = b"ed25519 seed"
_HARDENED = 0x80000000


@dataclass(frozen=True)
class Node:
    private_key: bytes
    chain_code: bytes


def _hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, "sha512").digest()


def master(seed: bytes) -> Node:
    i = _hmac_sha512(_ED25519_MASTER_KEY, seed)
    return Node(i[:32], i[32:])


def derive_child(parent: Node, index: int) -> Node:
    """One hardened child step. The hardened bit is added automatically."""
    hardened = index | _HARDENED
    data = b"\x00" + parent.private_key + hardened.to_bytes(4, "big")
    i = _hmac_sha512(parent.chain_code, data)
    return Node(i[:32], i[32:])


def derive_path(seed: bytes, path: str) -> Node:
    node = master(seed)
    for index in parse_path(path):
        node = derive_child(node, index)
    return node


def parse_path(path: str) -> list[int]:
    trimmed = path.strip()
    if trimmed not in ("m",) and not trimmed.startswith("m/"):
        raise ValueError(f"path must start with 'm': {path}")
    if trimmed == "m":
        return []
    result: list[int] = []
    for raw in trimmed[2:].split("/"):
        cleaned = raw.rstrip("'").rstrip("hH")
        try:
            n = int(cleaned)
        except ValueError as exc:
            raise ValueError(f"bad path segment: '{raw}'") from exc
        if n < 0 or n & _HARDENED:
            raise ValueError(f"index out of range: {raw}")
        result.append(n)
    return result

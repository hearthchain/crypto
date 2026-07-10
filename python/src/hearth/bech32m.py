"""Bech32m encoder/decoder (BIP-350), checksum constant 0x2bc830a3."""

from __future__ import annotations

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_CONST = 0x2BC830A3
_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def encode(hrp: str, data: bytes) -> str:
    values = _convert_bits(list(data), 8, 5, pad=True)
    if values is None:
        raise ValueError("cannot regroup payload bits")
    checksum = _create_checksum(hrp, values)
    return hrp + "1" + "".join(_CHARSET[d] for d in values + checksum)


def decode_raw(s: str) -> tuple[str, list[int]] | None:
    """Verify structure + checksum only; return (hrp, raw 5-bit data groups)."""
    if s != s.lower() and s != s.upper():
        return None
    lower = s.lower()
    pos = lower.rfind("1")
    if pos < 1 or len(lower) - pos - 1 < 6:
        return None
    hrp, data_part = lower[:pos], lower[pos + 1 :]
    values: list[int] = []
    for ch in data_part:
        idx = _CHARSET.find(ch)
        if idx < 0:
            return None
        values.append(idx)
    if _polymod(_hrp_expand(hrp) + values) != _CONST:
        return None
    return hrp, values[:-6]


def decode(s: str) -> tuple[str, bytes] | None:
    """Decode into (hrp, payload bytes) — the byte-aligned form addresses use."""
    raw = decode_raw(s)
    if raw is None:
        return None
    hrp, values = raw
    data = _convert_bits(values, 5, 8, pad=False)
    if data is None:
        return None
    return hrp, bytes(data)


# --- internals -----------------------------------------------------------


def _polymod(values: list[int]) -> int:
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= _GEN[i]
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _create_checksum(hrp: str, data: list[int]) -> list[int]:
    values = _hrp_expand(hrp) + data + [0, 0, 0, 0, 0, 0]
    pm = _polymod(values) ^ _CONST
    return [(pm >> (5 * (5 - i))) & 31 for i in range(6)]


def _convert_bits(data: list[int], frm: int, to: int, pad: bool) -> list[int] | None:
    acc = 0
    bits = 0
    maxv = (1 << to) - 1
    out: list[int] = []
    for value in data:
        if value < 0 or (value >> frm) != 0:
            return None
        acc = (acc << frm) | value
        bits += frm
        while bits >= to:
            bits -= to
            out.append((acc >> bits) & maxv)
    if pad:
        if bits > 0:
            out.append((acc << (to - bits)) & maxv)
    elif bits >= frm or ((acc << (to - bits)) & maxv) != 0:
        return None
    return out

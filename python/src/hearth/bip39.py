"""BIP-39 mnemonic validation and seed derivation."""

from __future__ import annotations

import hashlib
import unicodedata
from functools import cache
from importlib.resources import files

_ITERATIONS = 2048
_SEED_LEN = 64
_VALID_WORD_COUNTS = {12, 15, 18, 21, 24}


@cache
def wordlist() -> tuple[str, ...]:
    text = files("hearth.data").joinpath("english.txt").read_text(encoding="utf-8")
    return tuple(line.strip() for line in text.splitlines() if line.strip())


@cache
def _word_index() -> dict[str, int]:
    return {word: i for i, word in enumerate(wordlist())}


def _normalize(text: str) -> str:
    return unicodedata.normalize("NFKD", text)


def validate(mnemonic: str) -> str | None:
    """Return an error message if invalid, else ``None`` (valid checksum)."""
    words = [w for w in _normalize(mnemonic).split(" ") if w]
    if len(words) not in _VALID_WORD_COUNTS:
        return f"word count must be 12/15/18/21/24, got {len(words)}"
    index = _word_index()
    indices: list[int] = []
    for word in words:
        if word not in index:
            return f"unknown word: '{word}'"
        indices.append(index[word])

    bits = [(i >> b) & 1 for i in indices for b in range(10, -1, -1)]
    checksum_bits = len(bits) // 33
    entropy_bits = len(bits) - checksum_bits
    entropy = _bits_to_bytes(bits[:entropy_bits])
    digest = hashlib.sha256(entropy).digest()
    expected = [(digest[i // 8] >> (7 - (i % 8))) & 1 for i in range(checksum_bits)]
    if expected != bits[entropy_bits:]:
        return "checksum mismatch"
    return None


def to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """Derive the 64-byte BIP-39 seed (PBKDF2-HMAC-SHA512, 2048 iterations)."""
    password = _normalize(mnemonic).encode("utf-8")
    salt = _normalize("mnemonic" + passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", password, salt, _ITERATIONS, _SEED_LEN)


def _bits_to_bytes(bits: list[int]) -> bytes:
    assert len(bits) % 8 == 0
    out = bytearray(len(bits) // 8)
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i : i + 8]:
            byte = (byte << 1) | b
        out[i // 8] = byte
    return bytes(out)

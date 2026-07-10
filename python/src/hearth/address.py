"""Account addresses: Bech32m(hrp, versionByte || SHA-256(publicKey)[0:20]).

The per-network HRP is a UX guard against sending to the wrong network; it is not
replay protection (that belongs in the signed transaction).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from . import bech32m, sodium

_ED25519_VERSION = 0x00
_HASH_LEN = 20


class Network(Enum):
    TESTNET = "hrtht"
    MAINNET = "hrthm"

    @property
    def hrp(self) -> str:
        return self.value

    @classmethod
    def by_hrp(cls, hrp: str) -> Network | None:
        return next((n for n in cls if n.value == hrp), None)


@dataclass(frozen=True)
class Address:
    network: Network
    hash: bytes
    version: int

    def encoded(self) -> str:
        return bech32m.encode(self.network.hrp, bytes([self.version]) + self.hash)

    def __str__(self) -> str:
        return self.encoded()


def from_public_key(public_key: bytes, network: Network) -> str:
    if len(public_key) != 32:
        raise ValueError("public key must be 32 bytes")
    digest = sodium.sha256(public_key)[:_HASH_LEN]
    return bech32m.encode(network.hrp, bytes([_ED25519_VERSION]) + digest)


def parse(s: str) -> Address | None:
    decoded = bech32m.decode(s)
    if decoded is None:
        return None
    hrp, payload = decoded
    network = Network.by_hrp(hrp)
    if network is None or len(payload) != _HASH_LEN + 1 or payload[0] != _ED25519_VERSION:
        return None
    return Address(network, payload[1:], payload[0])


def parse_for(s: str, expected: Network) -> Address | None:
    address = parse(s)
    if address is None or address.network != expected:
        return None
    return address

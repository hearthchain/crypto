"""The three role keys, derived from one BIP-39 seed at separate paths.

Signing and VRF keys use different hardened SLIP-0010 role indices so their
secret scalars are unrelated (removing the EdDSA/ECVRF shared-key risk). BLS
finality keys live in their own EIP-2333 tree (different curve).
"""

from __future__ import annotations

from . import bls, ed25519, slip10

_COIN_TYPE = 9381  # placeholder — register a SLIP-0044 value
_ROLE_SIGNING = 0
_ROLE_VRF = 1


def signing_path(account: int = 0) -> str:
    return f"m/44'/{_COIN_TYPE}'/{account}'/{_ROLE_SIGNING}'/0'"


def vrf_path(account: int = 0) -> str:
    return f"m/44'/{_COIN_TYPE}'/{account}'/{_ROLE_VRF}'/0'"


def bls_path(account: int = 0) -> str:
    return f"m/{bls.PURPOSE}/{_COIN_TYPE}/{account}/0"


def signing_key(seed: bytes, account: int = 0) -> ed25519.KeyPair:
    return ed25519.from_seed(slip10.derive_path(seed, signing_path(account)).private_key)


def vrf_key(seed: bytes, account: int = 0) -> ed25519.KeyPair:
    """Its ``.seed`` feeds ecvrf.prove; ``.public_key`` is the VRF public key."""
    return ed25519.from_seed(slip10.derive_path(seed, vrf_path(account)).private_key)


def bls_secret_key(seed: bytes, account: int = 0) -> bytes:
    """32-byte big-endian BLS12-381 scalar."""
    return bls.derive_path(seed, bls_path(account))

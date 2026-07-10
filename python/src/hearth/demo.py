"""Sample app for the hearth-chain crypto stack (Python / libsodium).

Usage:
    hearth-demo [mnemonic] [messageBase64] [alphaBase64]

With no arguments it uses a fixed demo mnemonic and sample payloads so the whole
pipeline (BIP-39 -> SLIP-0010 -> Ed25519 sign/verify -> ECVRF, plus BLS
derivation) runs end to end.
"""

from __future__ import annotations

import base64
import sys

import nacl

from . import address, bip39, ecvrf, ed25519, keytree
from .address import Network

_DEFAULT_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
_ACCOUNT = 0


def _section(title: str) -> None:
    print(f"\n== {title} ==")


def main() -> None:
    args = sys.argv[1:]
    mnemonic = args[0] if len(args) > 0 and args[0] else _DEFAULT_MNEMONIC
    message_b64 = args[1] if len(args) > 1 and args[1] else base64.b64encode(b"hearth-chain block header").decode()
    alpha_b64 = args[2] if len(args) > 2 and args[2] else base64.b64encode(b"epoch-42-slot-7").decode()

    _section("0) Inputs")
    print(f"crypto backend : libsodium via PyNaCl {nacl.__version__}")
    print(f"mnemonic       : {mnemonic}")
    error = bip39.validate(mnemonic)
    if error is not None:
        print(f"mnemonic check : INVALID ({error})")
        sys.exit(1)
    print("mnemonic check : VALID (BIP-39 checksum ok)")

    # (1) Derive keys — one mnemonic, separate per-role / per-curve trees
    _section("1) Key derivation (one mnemonic -> distinct signing / VRF / BLS keys)")
    seed = bip39.to_seed(mnemonic)
    signing = keytree.signing_key(seed, _ACCOUNT)  # ed25519, SLIP-0010 role 0
    vrf = keytree.vrf_key(seed, _ACCOUNT)  # ed25519, SLIP-0010 role 1
    bls_sk = keytree.bls_secret_key(seed, _ACCOUNT)  # BLS12-381, EIP-2333
    print(f"BIP-39 seed    : {seed.hex()}")
    print()
    print(f"signing path   : {keytree.signing_path(_ACCOUNT)}")
    print(f"signing pubkey : {signing.public_key.hex()}")
    print(f"address (main) : {address.from_public_key(signing.public_key, Network.MAINNET)}")
    print(f"address (test) : {address.from_public_key(signing.public_key, Network.TESTNET)}")
    print()
    print(f"VRF path       : {keytree.vrf_path(_ACCOUNT)}")
    print(f"VRF pubkey     : {vrf.public_key.hex()}  (distinct scalar from signing)")
    print()
    print(f"BLS path       : {keytree.bls_path(_ACCOUNT)}  (EIP-2333, no hardened marker)")
    print(f"BLS secret key : {bls_sk.hex()}  (32-byte scalar mod r)")

    # (2) Sign a base64 message with the signing key
    _section("2) Ed25519 sign (RFC 8032, Ledger-native) - signing key")
    message = base64.b64decode(message_b64)
    signature = signing.sign(message)
    print(f"message (b64)  : {message_b64}")
    print(f"message (hex)  : {message.hex()}")
    print(f"signature      : {signature.hex()}  (64 bytes)")

    # (3) Verify the signature
    _section("3) Ed25519 verify")
    print(f"verify         : {'VALID' if ed25519.verify(signature, message, signing.public_key) else 'INVALID'}")
    tampered = bytearray(message)
    if tampered:
        tampered[0] ^= 0x01
    ok = ed25519.verify(signature, bytes(tampered), signing.public_key)
    print(f"verify tampered: {'VALID (!)' if ok else 'INVALID (expected)'}")

    # (4) VRF sign and derive VRF value with the VRF key
    _section("4) ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381) - VRF key")
    alpha = base64.b64decode(alpha_b64)
    proof, beta = ecvrf.prove(vrf.seed, alpha)
    verified = ecvrf.verify(vrf.public_key, alpha, proof.bytes)
    print(f"alpha (b64)    : {alpha_b64}")
    print(f"alpha (hex)    : {alpha.hex()}")
    print(f"pi (proof)     : {proof.bytes.hex()}  (80 bytes)")
    print(f"  gamma        : {proof.gamma.hex()}")
    print(f"  c            : {proof.c.hex()}")
    print(f"  s            : {proof.s.hex()}")
    print(f"beta (VRF out) : {beta.hex()}  (64 bytes)")
    print(f"vrf verify     : {'VALID' if verified is not None else 'INVALID'}")
    if verified is not None:
        print(f"vrf verify beta: {verified.hex()}  (matches: {verified == beta})")


if __name__ == "__main__":
    main()

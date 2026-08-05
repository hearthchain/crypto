"""Delivering an API key to a confidential VM: the TD publishes an X25519
public key bound into its attestation report, the client seals the key to it
with HPKE, and only the TD can open it.

Usage:
    hearth-hpke-example
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from . import apikeyenvelope, hpke, x25519

# What the TD must place in the 64-byte REPORTDATA field of its quote.
_REPORT_DATA_CONTEXT = b"hearth-chain/tdx-hpke/v1"


def _section(title: str) -> None:
    print(f"\n== {title} ==")


def _failure_of(action: Callable[[], object]) -> str:
    try:
        action()
        return "OPENED — this should not happen"
    except ValueError as e:
        return f"rejected: {e}"


def main() -> None:
    _section("1) Inside the TD: generate the recipient keypair, bind it to the quote")
    # In a real TD this keypair is generated at boot and never leaves the
    # enclave; the private key is not persisted anywhere.
    enclave = x25519.generate_keypair()
    report_data = hashlib.sha512(_REPORT_DATA_CONTEXT + enclave.public_key).digest()
    print(f"public key (X25519, 32 B): {enclave.public_key.hex()}")
    print(f"REPORTDATA  (SHA-512, 64 B): {report_data.hex()}")
    print("  the TD puts this in its quote; the client recomputes it from the")
    print("  public key it was handed and compares — that is the binding.")

    _section("2) On the client: verify the quote, then seal the API key")
    print("(quote verification is out of scope here — check the signature chain,")
    print(" the TCB status, MRTD/RTMR, and that REPORTDATA matches the line above)")

    api_key = apikeyenvelope.random_api_key()
    not_after = (datetime.now(UTC) + timedelta(hours=24)).replace(microsecond=0)
    metadata = apikeyenvelope.Metadata("prod/ingest-api", not_after)
    envelope = apikeyenvelope.seal(enclave.public_key, api_key, metadata)

    print(f"api key      : {api_key}")
    print(f"key id       : {metadata.key_id}")
    print(f"expires      : {metadata.not_after}")
    print(f"suite        : {apikeyenvelope.DEFAULT_SUITE} (aead 0x{apikeyenvelope.DEFAULT_SUITE.aead_id:04x})")
    print(f"envelope     : {len(envelope)} bytes")
    print(f"  {envelope.hex()}")

    _section("3) Back inside the TD: open the envelope")
    opened = apikeyenvelope.open_(enclave.secret_key, envelope)
    print(f"recovered    : {opened.api_key.decode('ascii')}")
    print(f"key id       : {opened.metadata.key_id} (authenticated, not encrypted)")
    print(f"matches      : {opened.api_key.decode('ascii') == api_key}")
    opened.wipe()

    _section("4) What an attacker gets")
    # A different TD (or a replayed public key from another machine) cannot read it.
    impostor = x25519.generate_keypair()
    print(f"wrong recipient key  : {_failure_of(lambda: apikeyenvelope.open_(impostor.secret_key, envelope))}")

    # The metadata is authenticated, so it cannot be relabelled in flight:
    # flip the last byte of the expiry timestamp, still inside the header.
    relabelled = bytearray(envelope)
    metadata_end = 20 + ((envelope[18] << 8) | envelope[19])
    relabelled[metadata_end - 1] ^= 0x01
    relabelled_bytes = bytes(relabelled)
    print(
        "relabelled expiry    : "
        + _failure_of(lambda: apikeyenvelope.open_(enclave.secret_key, relabelled_bytes))
    )

    # And so is the ciphertext.
    tampered = bytearray(envelope)
    tampered[-1] ^= 0x01
    tampered_bytes = bytes(tampered)
    print("flipped tag byte     : " + _failure_of(lambda: apikeyenvelope.open_(enclave.secret_key, tampered_bytes)))

    # An expired envelope is rejected even though it decrypts correctly.
    stale = apikeyenvelope.seal(
        enclave.public_key,
        apikeyenvelope.random_api_key(),
        apikeyenvelope.Metadata("prod/ingest-api", datetime.now(UTC) - timedelta(seconds=1)),
    )
    print("expired envelope     : " + _failure_of(lambda: apikeyenvelope.open_(enclave.secret_key, stale)))

    _section("5) The raw HPKE layer")
    info = b"hearth-chain/example/v1"
    sealed = hpke.seal(hpke.Suite.X25519_SHA256_CHACHA20POLY1305, enclave.public_key, info, b"", b"any payload")
    print(f"enc (32 B)   : {sealed.enc.hex()}")
    print(f"ciphertext   : {sealed.ciphertext.hex()}")
    opened_payload = hpke.open_(
        hpke.Suite.X25519_SHA256_CHACHA20POLY1305, enclave.secret_key, sealed.enc, info, b"", sealed.ciphertext
    )
    print(f"opened       : {opened_payload.decode('utf-8')}")
    print()


if __name__ == "__main__":
    main()

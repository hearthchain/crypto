//! Self-consistency tests for the BLS Basic ciphersuite: sign -> verify,
//! aggregate verify, and public-key validity.

use hearth::bls_sig::*;

#[test]
fn sign_then_verify() {
    let sk = [0x42u8; 32];
    let msg = b"hello hearth";
    let pk = public_key_from_secret(&sk);
    let sig = sign_basic(&sk, msg);
    assert_eq!(pk.len(), PUBLIC_KEY_BYTES);
    assert_eq!(sig.len(), SIGNATURE_BYTES);
    assert!(is_valid_public_key(&pk));
    assert!(verify_basic(&pk, msg, &sig));
    // Wrong message fails.
    assert!(!verify_basic(&pk, b"other", &sig));
}

#[test]
fn verify_rejects_tampered_signature() {
    let sk = [0x11u8; 32];
    let msg = b"data";
    let pk = public_key_from_secret(&sk);
    let mut sig = sign_basic(&sk, msg);
    sig[0] ^= 0xff;
    assert!(!verify_basic(&pk, msg, &sig));
}

#[test]
fn aggregate_verify_same_message() {
    let sk1 = [1u8; 32];
    let sk2 = [2u8; 32];
    let msg = b"shared";
    let pk1 = public_key_from_secret(&sk1);
    let pk2 = public_key_from_secret(&sk2);
    let sig1 = sign_basic(&sk1, msg);
    let sig2 = sign_basic(&sk2, msg);

    // Aggregate the two signatures and verify against both public keys.
    let agg = aggregate_signatures(&[&sig1, &sig2]).expect("aggregate");
    assert!(fast_aggregate_verify_basic(&[&pk1, &pk2], msg, &agg));
}

#[test]
fn invalid_public_key_rejected() {
    assert!(!is_valid_public_key(&[0u8; 48])); // identity
    assert!(!is_valid_public_key(&[0u8; 47])); // wrong length
}

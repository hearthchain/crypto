//! Tests for the vanity grinder (`--features vanity`).
//!
//! The grinder replaces `curve25519-dalek`'s point arithmetic with its own, so
//! the first job here is proving the replacement agrees with dalek: the walk
//! `A_i = A_{i-1} + B`, the batched inversion, and the compression must produce
//! exactly the bytes dalek produces. The second job is the search itself, end to
//! end, on a pattern short enough to find instantly.

#![cfg(feature = "vanity")]

use std::sync::atomic::{AtomicBool, AtomicU64};

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use hearth::address;
use hearth::ed25519::{self, KeyPair};
use hearth::vanity::{self, Pattern, WINDOW};

/// A deterministic stand-in for a random scalar, so failures are reproducible.
fn scalar(n: u64) -> Scalar {
    Scalar::from_bytes_mod_order_wide(&hearth::primitives::sha512(&n.to_le_bytes()))
}

/// The grinder's own fixed-base multiplication must land where dalek's does.
/// Everything downstream is anchored to this starting point.
#[test]
fn mul_base_matches_dalek() {
    for n in [0u64, 1, 2, 7, 12345, u64::MAX] {
        let s = scalar(n);
        assert_eq!(
            vanity::walk(&s.to_bytes(), 1)[0],
            EdwardsPoint::mul_base(&(s + Scalar::ONE))
                .compress()
                .to_bytes(),
            "mul_base disagrees for scalar #{n}"
        );
    }
}

/// A full window walked and batch-compressed by the grinder must equal the same
/// points compressed one at a time by dalek. This covers the mixed addition, the
/// Montgomery trick, and the sign bit in the encoding.
#[test]
fn windowed_walk_matches_dalek() {
    let start = scalar(99);
    let encoded = vanity::walk(&start.to_bytes(), WINDOW);

    let mut expected = EdwardsPoint::mul_base(&start);
    for (i, actual) in encoded.iter().enumerate() {
        expected += ED25519_BASEPOINT_POINT;
        assert_eq!(
            *actual,
            expected.compress().to_bytes(),
            "walk disagrees at step {i}"
        );
    }
}

/// Candidate `i` of the walk must be the key for scalar `start + i`, which is
/// what makes the winner importable at all.
#[test]
fn walk_indices_match_scalars() {
    let start = scalar(4242);
    let encoded = vanity::walk(&start.to_bytes(), 8);
    for (i, public_key) in encoded.iter().enumerate() {
        let s = start + Scalar::from(i as u64 + 1);
        let key = KeyPair::from_scalar(&s.to_bytes()).unwrap();
        assert_eq!(&key.public_key, public_key, "scalar mismatch at step {i}");
    }
}

/// End to end: grind a short pattern, then confirm the emitted scalar really
/// produces that address through the ordinary library path, and signs for it.
#[test]
fn grinds_and_the_key_is_usable() {
    let pattern = Pattern::compile("qq").unwrap(); // 1024 expected candidates
    let counter = AtomicU64::new(0);
    let stop = AtomicBool::new(false);

    let hit = vanity::grind_from(&pattern, &vanity::random_start(), &counter, &stop)
        .expect("stop was never set");
    let found = hit
        .verify(&pattern, address::MAINNET_HRP)
        .expect("hit verifies");

    assert!(found.starts_with("hrth1qq"), "unexpected address {found}");

    // The scalar is a real, usable signing key for exactly that address.
    let key = KeyPair::from_scalar(&hit.scalar).unwrap();
    assert_eq!(key.to_address().to_bech32(address::MAINNET_HRP), found);
    let message = b"a transaction from a vanity address";
    assert!(ed25519::verify(
        &key.sign(message),
        message,
        &key.public_key
    ));

    // And it round-trips as an ordinary key.
    let reimported = KeyPair::from_expanded_key(&key.to_expanded_key()).unwrap();
    assert_eq!(reimported.sign(message), key.sign(message));
}

/// A hit reported for one pattern must not verify against a different one — the
/// guard that makes a fast-path bug cost hits rather than emit a wrong key.
#[test]
fn verify_rejects_a_mismatched_pattern() {
    let pattern = Pattern::compile("qq").unwrap();
    let counter = AtomicU64::new(0);
    let stop = AtomicBool::new(false);
    let hit = vanity::grind_from(&pattern, &vanity::random_start(), &counter, &stop).unwrap();

    assert!(hit.verify(&pattern, address::MAINNET_HRP).is_some());
    // "qq" addresses cannot also start with "pp".
    assert!(
        hit.verify(&Pattern::compile("pp").unwrap(), address::MAINNET_HRP)
            .is_none()
    );
    // Right pattern, wrong HRP: the body still matches, but the string differs.
    let testnet = hit.verify(&pattern, address::TESTNET_HRP).unwrap();
    assert!(testnet.starts_with("thrth1qq"));
}

#[test]
fn pattern_rejects_unusable_input() {
    // The bech32 alphabet has no b, i, o or 1 — a common surprise.
    for c in ["b", "i", "o", "1", "hearthb", "A"] {
        assert!(
            Pattern::compile(c).is_err(),
            "'{c}' should not compile as a pattern"
        );
    }
    assert!(Pattern::compile("").is_err());
    assert!(Pattern::compile("qqqqqqqqqqqqq").is_err()); // 13 > MAX_PATTERN_CHARS
    assert!(Pattern::compile("qqqqqqqqqqqq").is_ok()); // 12 is the limit

    assert_eq!(Pattern::compile("q").unwrap().expected_candidates(), 32.0);
    assert_eq!(
        Pattern::compile("hearth").unwrap().expected_candidates(),
        32f64.powi(6)
    );
}

/// Every character position must be matched, including the ones that straddle a
/// byte boundary — an off-by-one in the bit shifts would still pass a 1-char test.
#[test]
fn pattern_matches_every_position() {
    let key = KeyPair::from_scalar(&scalar(7).to_bytes()).unwrap();
    let address = key.to_address().to_bech32(address::MAINNET_HRP);
    let body = &address[address::MAINNET_HRP.len() + 1..];

    for n in 1..=12usize {
        let pattern = Pattern::compile(&body[..n]).unwrap();
        assert!(
            pattern.matches_public_key(&key.public_key),
            "pattern of length {n} did not match its own address"
        );
        // Perturbing the last character must break the match.
        let mut wrong: Vec<char> = body[..n].chars().collect();
        wrong[n - 1] = if wrong[n - 1] == 'q' { 'p' } else { 'q' };
        let wrong: String = wrong.into_iter().collect();
        assert!(
            !Pattern::compile(&wrong)
                .unwrap()
                .matches_public_key(&key.public_key),
            "pattern {wrong} matched an address it should not"
        );
    }
}

//! X25519 (RFC 7748) over raw 32-byte little-endian keys — the Diffie-Hellman
//! half of [`crate::hpke`]'s DHKEM.
//!
//! Unlike the rest of this crate this is *not* edwards25519 group arithmetic:
//! X25519 is the Montgomery-curve ladder. `curve25519-dalek`'s
//! `MontgomeryPoint::mul_clamped`/`mul_base_clamped` implement RFC 7748
//! directly (clamping the scalar internally), so no extra dependency is
//! needed beyond the `curve25519-dalek` this crate already uses for the VRF
//! math.

use curve25519_dalek::montgomery::MontgomeryPoint;
use rand::RngCore;
use rand::rngs::OsRng;

use crate::Error;

/// Size of both a private scalar and a public u-coordinate.
pub const KEY_BYTES: usize = 32;

/// An X25519 keypair in raw little-endian form.
#[derive(Clone)]
pub struct Keypair {
    pub public_key: [u8; KEY_BYTES],
    pub secret_key: [u8; KEY_BYTES],
}

/// A fresh keypair from the OS CSPRNG. The secret is 32 uniformly random
/// bytes; X25519 clamps them when they are used, so every draw is valid.
pub fn generate_keypair() -> Keypair {
    let mut secret_key = [0u8; KEY_BYTES];
    OsRng.fill_bytes(&mut secret_key);
    let public_key = public_key(&secret_key);
    Keypair {
        public_key,
        secret_key,
    }
}

/// The public key for a secret scalar, i.e. X25519(sk, 9).
pub fn public_key(secret_key: &[u8; KEY_BYTES]) -> [u8; KEY_BYTES] {
    MontgomeryPoint::mul_base_clamped(*secret_key).to_bytes()
}

/// The Diffie-Hellman shared coordinate X25519(sk, pk).
///
/// Returns [`Error::Crypto`] if `public_key` has small order (an all-zero
/// result), which RFC 9180 §7.1.4 requires KEMs to reject.
pub fn dh(
    secret_key: &[u8; KEY_BYTES],
    public_key: &[u8; KEY_BYTES],
) -> Result<[u8; KEY_BYTES], Error> {
    let shared = MontgomeryPoint(*public_key)
        .mul_clamped(*secret_key)
        .to_bytes();
    if shared.iter().all(|&b| b == 0) {
        return Err(Error::Crypto(
            "X25519: public key has small order".to_string(),
        ));
    }
    Ok(shared)
}

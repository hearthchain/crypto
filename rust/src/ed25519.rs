//! Ed25519 (EdDSA, RFC 8032) keys and signatures — the standard, Ledger-native
//! signature scheme. The same key material also backs the ECVRF (see
//! [`crate::ecvrf`]).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::Error;
use crate::primitives::sha512;

/// An Ed25519 keypair derived from a 32-byte seed.
#[derive(Clone)]
pub struct KeyPair {
    /// The 32-byte SLIP-0010 node key (the RFC 9381 "SK").
    pub seed: [u8; 32],
    /// The 32-byte compressed public key Y = x*B.
    pub public_key: [u8; 32],
}

impl KeyPair {
    pub fn from_seed(seed: &[u8]) -> Result<KeyPair, Error> {
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| Error::Length("Ed25519 seed must be 32 bytes"))?;
        let signing = SigningKey::from_bytes(&seed);
        Ok(KeyPair {
            seed,
            public_key: signing.verifying_key().to_bytes(),
        })
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(&self.seed).sign(message).to_bytes()
    }
}

pub fn verify(signature: &[u8], message: &[u8], public_key: &[u8]) -> bool {
    let Ok(pk) = <[u8; 32]>::try_from(public_key) else {
        return false;
    };
    let Ok(sig) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    match VerifyingKey::from_bytes(&pk) {
        Ok(vk) => vk.verify(message, &Signature::from_bytes(&sig)).is_ok(),
        Err(_) => false,
    }
}

/// RFC 8032 secret scalar: clamp(SHA-512(seed)[0..32]). Used by ECVRF.
pub(crate) fn secret_scalar(seed: &[u8]) -> [u8; 32] {
    let h = sha512(seed);
    let mut a = [0u8; 32];
    a.copy_from_slice(&h[..32]);
    a[0] &= 0xF8;
    a[31] = (a[31] & 0x7F) | 0x40;
    a
}

/// RFC 8032 nonce prefix: SHA-512(seed)[32..64]. Used by ECVRF nonce gen.
pub(crate) fn nonce_prefix(seed: &[u8]) -> [u8; 32] {
    let h = sha512(seed);
    let mut p = [0u8; 32];
    p.copy_from_slice(&h[32..64]);
    p
}

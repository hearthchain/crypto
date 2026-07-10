//! ECVRF-EDWARDS25519-SHA512-TAI, the RFC 9381 VRF (suite_string = 0x03). It
//! reuses the exact Ed25519 key: the VRF secret scalar is clamp(SHA-512(seed))
//! and the VRF public key is the Ed25519 public key.

use crate::ed25519::{nonce_prefix, secret_scalar};
use crate::primitives::{
    point_sub, scalar_add, scalar_mul, scalar_reduce, scalarmult_base_noclamp, scalarmult_noclamp,
    sha512,
};

const SUITE: u8 = 0x03;
const PROOF_LEN: usize = 80; // 32 + 16 + 32
const IDENTITY: [u8; 32] = {
    let mut a = [0u8; 32];
    a[0] = 1;
    a
};

/// A VRF proof pi = Gamma(32) || c(16) || s(32).
#[derive(Clone)]
pub struct Proof {
    pub gamma: [u8; 32],
    pub c: [u8; 16],
    pub s: [u8; 32],
}

impl Proof {
    pub fn bytes(&self) -> [u8; PROOF_LEN] {
        let mut out = [0u8; PROOF_LEN];
        out[..32].copy_from_slice(&self.gamma);
        out[32..48].copy_from_slice(&self.c);
        out[48..].copy_from_slice(&self.s);
        out
    }
}

/// Prove: returns the proof and the VRF output beta (64 bytes).
pub fn prove(seed: &[u8], alpha: &[u8]) -> (Proof, [u8; 64]) {
    let x = secret_scalar(seed);
    let y = scalarmult_base_noclamp(&x); // public key Y = x*B
    let h = encode_to_curve(&y, alpha);
    let gamma = scalarmult_noclamp(&x, &h).expect("Gamma = x*H");
    let k = nonce(seed, &h);
    let u = scalarmult_base_noclamp(&k); // U = k*B
    let v = scalarmult_noclamp(&k, &h).expect("V = k*H");
    let c = challenge(&y, &h, &gamma, &u, &v); // 16 bytes
    let mut c32 = [0u8; 32];
    c32[..16].copy_from_slice(&c);
    let s = scalar_add(&k, &scalar_mul(&c32, &x)); // s = k + c*x mod L
    let proof = Proof { gamma, c, s };
    let beta = proof_to_hash(&proof);
    (proof, beta)
}

/// Verify a proof; `Some(beta)` if valid, else `None`.
pub fn verify(public_key: &[u8], alpha: &[u8], pi: &[u8]) -> Option<[u8; 64]> {
    let proof = decode(pi)?;
    let h = encode_to_curve(public_key, alpha);
    let mut c32 = [0u8; 32];
    c32[..16].copy_from_slice(&proof.c);

    let s_b = scalarmult_base_noclamp(&proof.s);
    let c_y = scalarmult_noclamp(&c32, public_key)?;
    let u = point_sub(&s_b, &c_y)?; // U = s*B - c*Y
    let s_h = scalarmult_noclamp(&proof.s, &h)?;
    let c_gamma = scalarmult_noclamp(&c32, &proof.gamma)?;
    let v = point_sub(&s_h, &c_gamma)?; // V = s*H - c*Gamma

    if challenge(public_key, &h, &proof.gamma, &u, &v) == proof.c {
        Some(proof_to_hash(&proof))
    } else {
        None
    }
}

/// proof_to_hash: beta = SHA-512(suite || 0x03 || point_to_string(8*Gamma) || 0x00).
pub fn proof_to_hash(proof: &Proof) -> [u8; 64] {
    let gamma8 = cofactor_clear(&proof.gamma).expect("8*Gamma");
    let mut input = Vec::with_capacity(2 + 32 + 1);
    input.extend_from_slice(&[SUITE, 0x03]);
    input.extend_from_slice(&gamma8);
    input.push(0x00);
    sha512(&input)
}

pub fn decode(pi: &[u8]) -> Option<Proof> {
    if pi.len() != PROOF_LEN {
        return None;
    }
    let mut gamma = [0u8; 32];
    let mut c = [0u8; 16];
    let mut s = [0u8; 32];
    gamma.copy_from_slice(&pi[..32]);
    c.copy_from_slice(&pi[32..48]);
    s.copy_from_slice(&pi[48..80]);
    Some(Proof { gamma, c, s })
}

// --- internals -----------------------------------------------------------

/// ECVRF_encode_to_curve_try_and_increment (RFC 9381 §5.4.1.1).
fn encode_to_curve(pk: &[u8], alpha: &[u8]) -> [u8; 32] {
    for ctr in 0u16..=255 {
        let mut input = Vec::with_capacity(2 + pk.len() + alpha.len() + 2);
        input.extend_from_slice(&[SUITE, 0x01]);
        input.extend_from_slice(pk);
        input.extend_from_slice(alpha);
        input.push(ctr as u8);
        input.push(0x00);
        let hash = sha512(&input);
        if let Some(cleared) = cofactor_clear(&hash[..32])
            && cleared != IDENTITY
        {
            return cleared;
        }
    }
    panic!("encode_to_curve: no valid point found");
}

/// Multiply a compressed point by cofactor 8 via three doublings (on-curve check only).
fn cofactor_clear(p: &[u8]) -> Option<[u8; 32]> {
    let p2 = crate::primitives::point_add(p, p)?;
    let p4 = crate::primitives::point_add(&p2, &p2)?;
    crate::primitives::point_add(&p4, &p4)
}

/// ECVRF_nonce_generation_RFC8032 (RFC 9381 §5.4.2.2).
fn nonce(seed: &[u8], h: &[u8]) -> [u8; 32] {
    let mut input = nonce_prefix(seed).to_vec();
    input.extend_from_slice(h);
    scalar_reduce(&sha512(&input))
}

/// ECVRF_challenge_generation (RFC 9381 §5.4.3): first 16 bytes.
fn challenge(y: &[u8], h: &[u8], gamma: &[u8], u: &[u8], v: &[u8]) -> [u8; 16] {
    let mut input = Vec::new();
    input.extend_from_slice(&[SUITE, 0x02]);
    input.extend_from_slice(y);
    input.extend_from_slice(h);
    input.extend_from_slice(gamma);
    input.extend_from_slice(u);
    input.extend_from_slice(v);
    input.push(0x00);
    let full = sha512(&input);
    let mut c = [0u8; 16];
    c.copy_from_slice(&full[..16]);
    c
}

//! Low-level crypto primitives: hashing, HMAC, and the edwards25519
//! group/scalar arithmetic the VRF needs (via `curve25519-dalek`).
//!
//! Note on "noclamp": libsodium's `*_noclamp` multiplies by the raw 256-bit
//! scalar, whereas `Scalar` is always reduced mod L. We reduce first; this is
//! identical because every point we multiply here has order L
//! (`n*P == (n mod L)*P`), so results match the other implementations
//! byte-for-byte.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out.copy_from_slice(&Sha512::digest(data));
    out
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(data));
    out
}

pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = <Hmac<Sha512>>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let mut out = [0u8; 64];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

fn decompress(bytes: &[u8]) -> Option<EdwardsPoint> {
    let arr: [u8; 32] = bytes.try_into().ok()?;
    CompressedEdwardsY(arr).decompress()
}

fn scalar_from_le(n: &[u8]) -> Scalar {
    let mut a = [0u8; 32];
    a.copy_from_slice(n);
    Scalar::from_bytes_mod_order(a)
}

/// Point addition on compressed points; `None` if either is off-curve. Only an
/// on-curve check (accepts non-prime-order points), which is what RFC 9381
/// try-and-increment cofactor clearing needs.
pub fn point_add(p: &[u8], q: &[u8]) -> Option<[u8; 32]> {
    let a = decompress(p)?;
    let b = decompress(q)?;
    Some((a + b).compress().to_bytes())
}

pub fn point_sub(p: &[u8], q: &[u8]) -> Option<[u8; 32]> {
    let a = decompress(p)?;
    let b = decompress(q)?;
    Some((a - b).compress().to_bytes())
}

/// `n * p`; `None` if `p` is off-curve.
pub fn scalarmult_noclamp(n: &[u8], p: &[u8]) -> Option<[u8; 32]> {
    let point = decompress(p)?;
    Some((point * scalar_from_le(n)).compress().to_bytes())
}

/// `n * B`.
pub fn scalarmult_base_noclamp(n: &[u8]) -> [u8; 32] {
    EdwardsPoint::mul_base(&scalar_from_le(n))
        .compress()
        .to_bytes()
}

/// `x * y mod L`.
pub fn scalar_mul(x: &[u8], y: &[u8]) -> [u8; 32] {
    (scalar_from_le(x) * scalar_from_le(y)).to_bytes()
}

/// `x + y mod L`.
pub fn scalar_add(x: &[u8], y: &[u8]) -> [u8; 32] {
    (scalar_from_le(x) + scalar_from_le(y)).to_bytes()
}

/// Reduce a 64-byte little-endian value mod L to a 32-byte scalar.
pub fn scalar_reduce(wide: &[u8]) -> [u8; 32] {
    let mut w = [0u8; 64];
    w.copy_from_slice(wide);
    Scalar::from_bytes_mod_order_wide(&w).to_bytes()
}

//! BLS12-381 signatures (RFC draft-irtf-cfrg-bls-signature-05), mirroring
//! `tech.hearth.crypto.BlsKey` from the sibling Java module (which wraps blst).
//!
//! Scheme: public keys are 48-byte compressed G1 points, signatures are 96-byte
//! compressed G2 points. Only the **Basic** (unaugmented) ciphersuite is exposed
//! here (`..._NUL_` DST), matching what the node uses for block endorsements
//! (rogue-key defense is enforced out of band by the period-bound proof of
//! possession in `CommitToGenerationTransaction`).
//!
//! The secret scalar is the EIP-2333-derived 32-byte scalar (see `bls`); it is
//! loaded verbatim, not re-derived, matching the Java `BlsKey.fromSecretKey`.

use bls12_381::{Bls12, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use group::Curve;
use pairing::Engine;

/// The Basic ciphersuite DST (`BlsKey.DST_SIG_BASIC`).
pub const DST_SIG_BASIC: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
/// Compressed G1 public-key length in bytes.
pub const PUBLIC_KEY_BYTES: usize = 48;
/// Compressed G2 signature length in bytes.
pub const SIGNATURE_BYTES: usize = 96;

/// Derive the 48-byte compressed G1 public key from a 32-byte big-endian secret
/// scalar. Mirrors `BlsKey.fromSecretKey(...).publicKey()` (the scalar is used
/// as-is, not re-derived).
pub fn public_key_from_secret(scalar_32: &[u8]) -> [u8; PUBLIC_KEY_BYTES] {
    let sk = scalar_from_be32(scalar_32);
    let pk = G1Projective::generator() * sk;
    pk.to_affine().to_compressed()
}

/// `isValidPublicKey`: `bytes` decodes to a valid, non-identity G1 point in the
/// correct subgroup. Mirrors `BlsKey.isValidPublicKey`.
pub fn is_valid_public_key(bytes: &[u8]) -> bool {
    match decode_g1(bytes) {
        Some(pk) => !bool::from(pk.is_identity()),
        None => false,
    }
}

/// Sign `message` under the Basic ciphersuite, returning a 96-byte compressed
/// G2 signature. Mirrors `BlsKey.signBasic`.
pub fn sign_basic(scalar_32: &[u8], message: &[u8]) -> [u8; SIGNATURE_BYTES] {
    let sk = scalar_from_be32(scalar_32);
    let h = hash_to_g2(message);
    let sig = h * sk;
    sig.to_affine().to_compressed()
}

/// Verify a single signature under the Basic ciphersuite. Mirrors
/// `BlsKey.verifyBasic`: `e(pk, H(m)) == e(g1, sig)`, after subgroup checks on
/// both the public key and the signature.
pub fn verify_basic(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let (Some(pk), Some(sig)) = (decode_g1(public_key), decode_g2(signature)) else {
        return false;
    };
    if bool::from(pk.is_identity()) || bool::from(sig.is_identity()) {
        return false;
    }
    let h = hash_to_g2(message).to_affine();
    let e1 = <Bls12 as Engine>::pairing(&pk, &h);
    let e2 = <Bls12 as Engine>::pairing(&G1Affine::generator(), &sig);
    e1 == e2
}

/// Aggregate G2 signatures (point addition). Mirrors `BlsKey.aggregate`.
pub fn aggregate_signatures(signatures: &[&[u8]]) -> Option<[u8; SIGNATURE_BYTES]> {
    if signatures.is_empty() {
        return None;
    }
    let mut acc = G2Projective::from(decode_g2(signatures[0])?);
    for sig in &signatures[1..] {
        acc += decode_g2(sig)?;
    }
    Some(acc.to_affine().to_compressed())
}

/// Aggregate G1 public keys (point addition). Mirrors `BlsKey.aggregatePublicKeys`.
pub fn aggregate_public_keys(public_keys: &[&[u8]]) -> Option<[u8; PUBLIC_KEY_BYTES]> {
    if public_keys.is_empty() {
        return None;
    }
    let mut acc = G1Projective::from(decode_g1(public_keys[0])?);
    for pk in &public_keys[1..] {
        acc += decode_g1(pk)?;
    }
    Some(acc.to_affine().to_compressed())
}

/// Fast aggregate verify: every signer signed the same `message`. One pairing
/// check against the aggregate of their public keys. Mirrors
/// `BlsKey.fastAggregateVerifyBasic`.
pub fn fast_aggregate_verify_basic(
    public_keys: &[&[u8]],
    message: &[u8],
    aggregate_signature: &[u8],
) -> bool {
    let Some(agg_pk) = aggregate_public_keys(public_keys) else {
        return false;
    };
    verify_basic(&agg_pk, message, aggregate_signature)
}

/// Hash a message to a G2 point (XMD:SHA-256, SSWU RO, the Basic DST).
fn hash_to_g2(message: &[u8]) -> G2Projective {
    use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
    <G2Projective as HashToCurve<ExpandMsgXmd<sha2_09::Sha256>>>::hash_to_curve(
        message,
        DST_SIG_BASIC,
    )
}

fn scalar_from_be32(scalar_32: &[u8]) -> Scalar {
    let mut bytes = [0u8; 32];
    let n = scalar_32.len().min(32);
    bytes[32 - n..].copy_from_slice(&scalar_32[..n]);
    // BLS12-381 Scalar::from_bytes expects little-endian; the EIP-2333 scalar
    // is big-endian, so reverse (the Java side loads it via from_bendian).
    bytes.reverse();
    Scalar::from_bytes(&bytes).unwrap_or(Scalar::zero())
}

/// Decode a compressed G1 public key, requiring it to be a valid prime-order
/// (subgroup) point. Returns `None` for identity, malformed, or off-subgroup.
fn decode_g1(bytes: &[u8]) -> Option<G1Affine> {
    if bytes.len() != PUBLIC_KEY_BYTES {
        return None;
    }
    let arr: [u8; 48] = bytes.try_into().ok()?;
    let pk: G1Affine = G1Affine::from_compressed(&arr).into_option()?;
    bool::from(pk.is_torsion_free()).then_some(pk)
}

/// Decode a compressed G2 signature, requiring a valid prime-order point.
fn decode_g2(bytes: &[u8]) -> Option<G2Affine> {
    if bytes.len() != SIGNATURE_BYTES {
        return None;
    }
    let arr: [u8; 96] = bytes.try_into().ok()?;
    let sig: G2Affine = G2Affine::from_compressed(&arr).into_option()?;
    bool::from(sig.is_torsion_free()).then_some(sig)
}

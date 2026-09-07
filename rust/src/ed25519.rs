//! Ed25519 (EdDSA, RFC 8032) keys and signatures — the standard, Ledger-native
//! signature scheme. The same key material also backs the ECVRF (see
//! [`crate::ecvrf`]).
//!
//! # One key type, several ways in
//!
//! Every Ed25519 secret is, at signing time, a pair: the secret scalar `a` and
//! the nonce prefix. A seed is just a compact way to generate that pair by
//! hashing (RFC 8032 §5.1.5). So a key derived from a mnemonic and a key
//! imported from a raw scalar are the same kind of object here, and callers
//! never branch on where one came from:
//!
//! - [`KeyPair::from_seed`] — a 32-byte seed, what [`crate::keytree`] derives
//!   from a mnemonic;
//! - [`KeyPair::from_expanded_key`] — the pair directly, `scalar ‖ noncePrefix`;
//! - [`KeyPair::from_scalar`] — a bare scalar, with the prefix derived from it.
//!
//! [`KeyPair::public_key`], [`KeyPair::sign`] and [`KeyPair::to_expanded_key`]
//! behave identically for all of them, and a verifier cannot tell them apart.
//! The seedless entries exist because some keys cannot have a seed — the
//! motivating case being vanity-address search (see `src/bin/hearth-vanity.rs`),
//! where candidates are walked by repeated point addition and no seed hashes to
//! the scalar that wins.
//!
//! What a seedless key genuinely cannot do is anything that needs the seed *as
//! such*: it has no mnemonic and no SLIP-0010 path, so it cannot feed
//! [`crate::ecvrf`], whose nonce derivation takes the seed (and whose key lives
//! at a different path anyway).
//!
//! # Handling the nonce prefix
//!
//! The prefix is **secret key material**, not a label. EdDSA's per-signature
//! nonce is `r = SHA-512(prefix ‖ message)`; anyone who learns the prefix learns
//! `r` for any message this key signs, and recovers the secret scalar from a
//! single signature via `a = (S - r) / k`. A generator that produces keys in
//! expanded form must draw the prefix from a CSPRNG — never from a search
//! counter, a candidate index, or anything else derived from public data.
//! [`KeyPair::from_scalar`] sidesteps that trap by deriving the prefix from the
//! secret scalar itself.

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::Error;
use crate::primitives::sha512;

/// Size of the expanded secret: scalar(32) || nonce prefix(32).
pub const EXPANDED_KEY_BYTES: usize = 64;

/// Domain separation tag for [`KeyPair::from_scalar`]: the prefix is
/// `SHA-512(SCALAR_EXPAND_DST ‖ scalar)[32..64]`. Fixed across all
/// implementations — changing it changes every key imported that way.
pub const SCALAR_EXPAND_DST: &str = "hearth-chain/ed25519-scalar-expand/v1";

/// An Ed25519 keypair.
#[derive(Clone)]
pub struct KeyPair {
    /// The 32-byte SLIP-0010 node key (the RFC 9381 "SK"), when a seed produced
    /// this key. `None` for a seedless import.
    seed: Option<[u8; 32]>,
    /// The RFC 8032 secret scalar, little-endian, used verbatim.
    scalar: [u8; 32],
    /// The RFC 8032 nonce prefix.
    prefix: [u8; 32],
    /// The 32-byte compressed public key `A = [a]B`.
    pub public_key: [u8; 32],
}

impl KeyPair {
    /// Derive a keypair from a 32-byte seed (RFC 8032 §5.1.5).
    pub fn from_seed(seed: &[u8]) -> Result<KeyPair, Error> {
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| Error::Length("Ed25519 seed must be 32 bytes"))?;
        let signing = SigningKey::from_bytes(&seed);
        Ok(KeyPair {
            seed: Some(seed),
            scalar: secret_scalar(&seed),
            prefix: nonce_prefix(&seed),
            public_key: signing.verifying_key().to_bytes(),
        })
    }

    /// Import `scalar[32] || noncePrefix[32]`, both little-endian as RFC 8032
    /// writes them.
    ///
    /// The scalar is taken verbatim. It is **not** required to be clamped —
    /// that is the point of this entry: a scalar arrived at by repeated point
    /// addition has no reason to satisfy the clamping bits, and EdDSA does not
    /// need it to (clamping guards X25519's cofactor and a ladder's timing, not
    /// the signature equation). It is not required to be reduced mod L either,
    /// so a seed-derived key exports and re-imports byte-for-byte.
    ///
    /// Rejected: a wrong length, a scalar with the high bit set (above the
    /// 255-bit range the group operations accept), or a scalar that is zero mod
    /// L — whose public key is the identity point, which [`verify`] rejects for
    /// every signature.
    pub fn from_expanded_key(expanded: &[u8]) -> Result<KeyPair, Error> {
        let expanded: [u8; EXPANDED_KEY_BYTES] = expanded
            .try_into()
            .map_err(|_| Error::Length("expanded key must be 64 bytes"))?;
        let mut scalar = [0u8; 32];
        let mut prefix = [0u8; 32];
        scalar.copy_from_slice(&expanded[..32]);
        prefix.copy_from_slice(&expanded[32..]);
        KeyPair::from_parts(scalar, prefix)
    }

    /// Import a bare 32-byte secret scalar, deriving the nonce prefix from it as
    /// `SHA-512(`[`SCALAR_EXPAND_DST`]` ‖ scalar)[32..64]` — the same shape RFC
    /// 8032 uses when it splits a hash into scalar and prefix, with the scalar
    /// in place of the seed.
    ///
    /// This is what a key generator that only ever computes scalars — a vanity
    /// grinder walking `a_i = a_{i-1} + 1` — should emit: 32 bytes, and any
    /// implementation reconstructs the identical key. It also removes the
    /// sharpest edge in [`KeyPair::from_expanded_key`], since the prefix is then
    /// a one-way function of secret material rather than something the generator
    /// has to remember to draw from a CSPRNG.
    ///
    /// The derived prefix is not the one any seed would produce, so this is not
    /// a way back to a mnemonic.
    pub fn from_scalar(scalar: &[u8]) -> Result<KeyPair, Error> {
        let scalar: [u8; 32] = scalar
            .try_into()
            .map_err(|_| Error::Length("secret scalar must be 32 bytes"))?;
        let mut input = SCALAR_EXPAND_DST.as_bytes().to_vec();
        input.extend_from_slice(&scalar);
        let mut prefix = [0u8; 32];
        prefix.copy_from_slice(&sha512(&input)[32..]);
        KeyPair::from_parts(scalar, prefix)
    }

    fn from_parts(scalar: [u8; 32], prefix: [u8; 32]) -> Result<KeyPair, Error> {
        if scalar[31] & 0x80 != 0 {
            return Err(Error::Crypto(
                "secret scalar must be below 2^255 (high bit clear)".into(),
            ));
        }
        let a = Scalar::from_bytes_mod_order(scalar);
        if a == Scalar::ZERO {
            return Err(Error::Crypto("secret scalar must not be zero mod L".into()));
        }
        Ok(KeyPair {
            seed: None,
            scalar,
            prefix,
            public_key: EdwardsPoint::mul_base(&a).compress().to_bytes(),
        })
    }

    /// The 32-byte SLIP-0010 node key, when a seed produced this key. `None` for
    /// a seedless import — [`crate::ecvrf`] needs this and so cannot be fed one.
    pub fn seed(&self) -> Option<&[u8; 32]> {
        self.seed.as_ref()
    }

    /// The expanded secret, `scalar[32] || noncePrefix[32]` — the form
    /// [`KeyPair::from_expanded_key`] takes back, and everything needed to sign.
    /// For a seed-derived key this is `clamp(SHA-512(seed)[0..32]) ‖
    /// SHA-512(seed)[32..64]`, i.e. exactly what signing uses internally anyway.
    ///
    /// Treat the result as the private key it is.
    pub fn to_expanded_key(&self) -> [u8; EXPANDED_KEY_BYTES] {
        let mut out = [0u8; EXPANDED_KEY_BYTES];
        out[..32].copy_from_slice(&self.scalar);
        out[32..].copy_from_slice(&self.prefix);
        out
    }

    /// This key's (network-independent) account address.
    pub fn to_address(&self) -> crate::address::Address {
        crate::address::Address::from_public_key(&self.public_key)
            .expect("public_key is always 32 bytes")
    }

    /// Produce a detached Ed25519 signature.
    ///
    /// A key that came from a seed takes `ed25519-dalek`'s signer, which wants
    /// the seed; any other key takes [`sign_with_scalar`]. That is an internal
    /// shortcut, not a difference in behaviour — the two are the same
    /// computation and, for the same key, return the same bytes, which
    /// `tests/vectors.rs` pins.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        match &self.seed {
            Some(seed) => SigningKey::from_bytes(seed).sign(message).to_bytes(),
            None => sign_with_scalar(message, &self.scalar, &self.prefix, &self.public_key),
        }
    }
}

/// RFC 8032 §5.1.6 signing straight from an expanded secret (scalar + nonce
/// prefix), for keys that have no seed behind them.
///
/// `scalar` is used verbatim — not clamped, and not required to be reduced mod L
/// (a seed-derived scalar never is: clamping sets bit 254, putting it above L).
/// Every step is mod L, so both forms sign the same and produce byte-identical
/// signatures.
fn sign_with_scalar(
    message: &[u8],
    scalar: &[u8; 32],
    prefix: &[u8; 32],
    public_key: &[u8; 32],
) -> [u8; 64] {
    let mut buf = prefix.to_vec();
    buf.extend_from_slice(message);
    let r = Scalar::from_bytes_mod_order_wide(&sha512(&buf)); // r = H(prefix ‖ M) mod L
    let r_bytes = EdwardsPoint::mul_base(&r).compress().to_bytes(); // R = [r]B

    let mut buf = r_bytes.to_vec();
    buf.extend_from_slice(public_key);
    buf.extend_from_slice(message);
    let k = Scalar::from_bytes_mod_order_wide(&sha512(&buf)); // k = H(R ‖ A ‖ M) mod L

    let s = r + k * Scalar::from_bytes_mod_order(*scalar); // S = r + k*a mod L

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_bytes);
    sig[32..].copy_from_slice(&s.to_bytes());
    sig
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

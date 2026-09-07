//! Vanity address search: find a signing key whose address starts with a chosen
//! string.
//!
//! # Why this needs its own arithmetic
//!
//! The obvious loop — pick a random seed, derive the key, check the address —
//! costs a full fixed-base scalar multiplication per candidate, because
//! `seed → scalar` runs through SHA-512 and is not homomorphic. Walking scalars
//! instead makes each step a single point addition:
//!
//! ```text
//!     a_i = a_{i-1} + 1        A_i = A_{i-1} + B
//! ```
//!
//! which is why [`crate::ed25519::KeyPair::from_scalar`] exists: the winner is a
//! scalar with no seed behind it.
//!
//! That leaves one expensive step per candidate — compressing `A_i` needs `1/Z`,
//! a field inversion costing ~250 squarings, which dwarfs the addition. The fix
//! is Montgomery's trick: accumulate a window of [`WINDOW`] points, invert the
//! product once, and unwind, so each candidate pays ~3 multiplications instead of
//! an inversion. `curve25519-dalek` cannot express that — it exposes no field
//! type and no coordinates — so this module carries a small `Ext`/`Fe` layer over
//! `fiat-crypto`'s formally verified field arithmetic. Measured on an M4-class
//! core, the three variants run at roughly:
//!
//! | loop | keys/s/core |
//! |---|---|
//! | seed → key → address (naive) | 0.12 M |
//! | walk + `dalek::compress` per candidate | 0.49 M |
//! | walk + batched inversion (this module) | 7.0 M |
//!
//! # Correctness
//!
//! The fast path only *selects* candidates. Every hit is re-derived
//! independently through the ordinary library path — `KeyPair::from_scalar` then
//! [`crate::address::Address::from_public_key`] — and discarded unless the
//! address really matches ([`Hit::verify`]). A bug in the arithmetic below can
//! therefore cost hits, but cannot emit a wrong key. `tests/vanity.rs` also pins
//! this module's point walk against `curve25519-dalek` directly.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use curve25519_dalek::scalar::Scalar;
use fiat_crypto::curve25519_64::*;

use crate::Error;
use crate::bech32m;
use crate::ed25519::KeyPair;
use crate::primitives::sha256;

/// Candidates accumulated before one batched field inversion.
pub const WINDOW: usize = 1024;

/// The longest pattern that fits the 64-bit fast comparison (12 × 5 = 60 bits).
/// Far beyond reach anyway: 32^12 ≈ 1.2e18 candidates.
pub const MAX_PATTERN_CHARS: usize = 12;

// --- pattern -------------------------------------------------------------

/// A compiled address prefix to search for.
///
/// An address is `Bech32m(hrp, SHA-256(publicKey)[0:20])` with no version byte,
/// so the 20-byte hash maps to exactly 32 data characters and character *j* is
/// bits `[5j, 5j+5)` of the hash. A prefix pattern is therefore a plain mask and
/// value over the first 8 bytes of the digest — no bech32m encoding in the inner
/// loop, and every character is fully free.
#[derive(Clone, Debug)]
pub struct Pattern {
    text: String,
    mask: u64,
    value: u64,
}

impl Pattern {
    /// Compile a prefix — the characters that must follow `<hrp>1`.
    pub fn compile(text: &str) -> Result<Pattern, Error> {
        if text.is_empty() {
            return Err(Error::Pattern("pattern must not be empty".into()));
        }
        if text.len() > MAX_PATTERN_CHARS {
            return Err(Error::Pattern(format!(
                "pattern is limited to {MAX_PATTERN_CHARS} characters (32^{} candidates already)",
                text.len()
            )));
        }
        let mut mask = 0u64;
        let mut value = 0u64;
        for (j, c) in text.chars().enumerate() {
            let idx = bech32m::charset_index(c).ok_or_else(|| {
                Error::Pattern(format!(
                    "'{c}' is not a bech32 character; the alphabet excludes b, i, o and 1"
                ))
            })?;
            let shift = 64 - 5 * (j + 1);
            mask |= 0x1f << shift;
            value |= (idx as u64) << shift;
        }
        Ok(Pattern {
            text: text.to_string(),
            mask,
            value,
        })
    }

    /// The pattern as typed.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Expected candidates per hit: `32^len`.
    pub fn expected_candidates(&self) -> f64 {
        32f64.powi(self.text.chars().count() as i32)
    }

    /// Whether an Ed25519 public key's address starts with this pattern. The
    /// ordinary-path equivalent of what the inner loop tests.
    pub fn matches_public_key(&self, public_key: &[u8]) -> bool {
        crate::address::Address::from_public_key(public_key)
            .is_ok_and(|_| self.matches(&sha256(public_key)))
    }

    #[inline(always)]
    fn matches(&self, digest: &[u8; 32]) -> bool {
        let head = u64::from_be_bytes(digest[..8].try_into().unwrap());
        head & self.mask == self.value
    }
}

// --- results -------------------------------------------------------------

/// A found key: the secret scalar, and the address it produces.
#[derive(Clone)]
pub struct Hit {
    /// The secret scalar, little-endian — feed it to [`KeyPair::from_scalar`].
    pub scalar: [u8; 32],
    /// How many candidates this thread tried before landing on it.
    pub tries: u64,
}

impl Hit {
    /// Re-derive the key through the ordinary library path and confirm the
    /// address matches. Returns the address string, or `None` if the fast path
    /// produced something that does not actually match — which would be a bug in
    /// this module, never a key handed to the caller.
    pub fn verify(&self, pattern: &Pattern, hrp: &str) -> Option<String> {
        let key = KeyPair::from_scalar(&self.scalar).ok()?;
        let address = key.to_address().to_bech32(hrp);
        let body = address.strip_prefix(hrp)?.strip_prefix('1')?;
        body.starts_with(pattern.text()).then_some(address)
    }
}

// --- the search ----------------------------------------------------------

/// Draw a worker's starting scalar from the OS CSPRNG, uniformly mod L.
///
/// This is the one place the security of a found key is decided. The winner is
/// `start + tries` and `tries` is printed, so anyone who can guess `start` can
/// recompute the private key from the public address. `profanity` drew its start
/// from a 32-bit seed, which made every address it ever produced brute-forceable
/// — the bug behind the 2022 Wintermute loss. Wide reduction of 64 random bytes
/// keeps the result unbiased mod L.
pub fn random_start() -> [u8; 32] {
    use rand::RngCore;
    let mut wide = [0u8; 64];
    rand::rngs::OsRng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide).to_bytes()
}

/// Walks `A_i = A_{i-1} + B` a window at a time, compressing each window with a
/// single batched inversion.
///
/// The batching is why this exists as a type: the inversion can only be
/// amortized across candidates that are computed together, so the walk has to
/// hand back a whole window at once rather than one point at a time.
struct Walker {
    point: Ext,
    base: Niels,
    xs: Vec<Fe>,
    ys: Vec<Fe>,
    zs: Vec<Fe>,
    partials: Vec<Fe>,
}

impl Walker {
    fn new(start: &[u8; 32]) -> Walker {
        Walker {
            point: Ext::mul_base(&Scalar::from_bytes_mod_order(*start)),
            base: Niels::basepoint(),
            xs: vec![Fe::ZERO; WINDOW],
            ys: vec![Fe::ZERO; WINDOW],
            zs: vec![Fe::ZERO; WINDOW],
            partials: vec![Fe::ZERO; WINDOW],
        }
    }

    /// Advance [`WINDOW`] steps, writing each step's compressed public key into
    /// `out`. Candidate `out[i]` is the key for scalar `start + walked + i + 1`.
    fn next_window(&mut self, out: &mut [[u8; 32]]) {
        for i in 0..WINDOW {
            self.point = self.point.add_base(&self.base);
            self.xs[i] = self.point.x;
            self.ys[i] = self.point.y;
            self.zs[i] = self.point.z;
        }

        // Montgomery's trick: one inversion for the whole window. Forward pass
        // stores the running product before each Z, the backward pass peels them
        // off, so each candidate costs 3 multiplications instead of an inversion.
        let mut acc = Fe::ONE;
        for i in 0..WINDOW {
            self.partials[i] = acc;
            acc = acc.mul(&self.zs[i]);
        }
        let mut inv = acc.invert();
        for i in (0..WINDOW).rev() {
            let z_inv = inv.mul(&self.partials[i]);
            inv = inv.mul(&self.zs[i]);
            out[i] = Ext {
                x: self.xs[i],
                y: self.ys[i],
                z: self.zs[i],
                t: Fe::ZERO,
            }
            .compress_with(&z_inv);
        }
    }
}

/// The compressed public keys for scalars `start + 1 ..= start + count`, by the
/// same walk the grinder uses.
///
/// Exposed so a caller can reproduce or audit a search — and so the test suite
/// can hold this arithmetic against `curve25519-dalek` point for point.
pub fn walk(start: &[u8; 32], count: usize) -> Vec<[u8; 32]> {
    let mut walker = Walker::new(start);
    let mut window = vec![[0u8; 32]; WINDOW];
    let mut out = Vec::with_capacity(count);
    while out.len() < count {
        walker.next_window(&mut window);
        let take = (count - out.len()).min(WINDOW);
        out.extend_from_slice(&window[..take]);
    }
    out
}

/// Walk candidates from `start`, returning the first whose address matches.
///
/// `start` is this worker's secret starting scalar and **must** come from a
/// CSPRNG — use [`random_start`]. The winning scalar is `start + tries`, so a
/// guessable start is a guessable key.
///
/// Returns `None` only when `stop` is set. `counter` is advanced by [`WINDOW`]
/// per batch so a caller can report a rate.
pub fn grind_from(
    pattern: &Pattern,
    start: &[u8; 32],
    counter: &AtomicU64,
    stop: &AtomicBool,
) -> Option<Hit> {
    let mut walker = Walker::new(start);
    let mut window = vec![[0u8; 32]; WINDOW];
    let mut walked: u64 = 0;

    loop {
        if stop.load(Ordering::Relaxed) {
            return None;
        }
        walker.next_window(&mut window);
        for (i, public_key) in window.iter().enumerate() {
            if pattern.matches(&sha256(public_key)) {
                let tries = walked + i as u64 + 1;
                let scalar = Scalar::from_bytes_mod_order(*start) + Scalar::from(tries);
                counter.fetch_add(i as u64 + 1, Ordering::Relaxed);
                return Some(Hit {
                    scalar: scalar.to_bytes(),
                    tries,
                });
            }
        }
        walked += WINDOW as u64;
        counter.fetch_add(WINDOW as u64, Ordering::Relaxed);
    }
}

// --- field arithmetic (fiat-crypto) --------------------------------------

/// A field element mod 2^255 - 19, held in fiat-crypto's tight representation.
#[derive(Clone, Copy)]
pub(crate) struct Fe(fiat_25519_tight_field_element);

impl Fe {
    pub(crate) const ZERO: Fe = Fe(fiat_25519_tight_field_element([0; 5]));
    pub(crate) const ONE: Fe = Fe(fiat_25519_tight_field_element([1, 0, 0, 0, 0]));

    fn from_bytes(bytes: &[u8; 32]) -> Fe {
        let mut out = fiat_25519_tight_field_element([0; 5]);
        fiat_25519_from_bytes(&mut out, bytes);
        Fe(out)
    }

    pub(crate) fn to_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        fiat_25519_to_bytes(&mut out, &self.0);
        out
    }

    #[inline(always)]
    fn loose(&self) -> fiat_25519_loose_field_element {
        let mut out = fiat_25519_loose_field_element([0; 5]);
        fiat_25519_relax(&mut out, &self.0);
        out
    }

    #[inline(always)]
    pub(crate) fn mul(&self, rhs: &Fe) -> Fe {
        let mut out = fiat_25519_tight_field_element([0; 5]);
        fiat_25519_carry_mul(&mut out, &self.loose(), &rhs.loose());
        Fe(out)
    }

    #[inline(always)]
    fn square(&self) -> Fe {
        let mut out = fiat_25519_tight_field_element([0; 5]);
        fiat_25519_carry_square(&mut out, &self.loose());
        Fe(out)
    }

    #[inline(always)]
    fn add(&self, rhs: &Fe) -> Fe {
        let mut loose = fiat_25519_loose_field_element([0; 5]);
        fiat_25519_add(&mut loose, &self.0, &rhs.0);
        let mut out = fiat_25519_tight_field_element([0; 5]);
        fiat_25519_carry(&mut out, &loose);
        Fe(out)
    }

    #[inline(always)]
    fn sub(&self, rhs: &Fe) -> Fe {
        let mut loose = fiat_25519_loose_field_element([0; 5]);
        fiat_25519_sub(&mut loose, &self.0, &rhs.0);
        let mut out = fiat_25519_tight_field_element([0; 5]);
        fiat_25519_carry(&mut out, &loose);
        Fe(out)
    }

    #[inline(always)]
    fn negate(&self) -> Fe {
        let mut loose = fiat_25519_loose_field_element([0; 5]);
        fiat_25519_opp(&mut loose, &self.0);
        let mut out = fiat_25519_tight_field_element([0; 5]);
        fiat_25519_carry(&mut out, &loose);
        Fe(out)
    }

    fn square_n(&self, n: usize) -> Fe {
        let mut r = *self;
        for _ in 0..n {
            r = r.square();
        }
        r
    }

    /// `self^(p-2)`, the field inverse, by the standard curve25519 addition
    /// chain (254 squarings + 11 multiplications). Called once per window.
    pub(crate) fn invert(&self) -> Fe {
        let z2 = self.square();
        let z9 = z2.square_n(2).mul(self);
        let z11 = z9.mul(&z2);
        let z_5_0 = z11.square().mul(&z9);
        let z_10_0 = z_5_0.square_n(5).mul(&z_5_0);
        let z_20_0 = z_10_0.square_n(10).mul(&z_10_0);
        let z_40_0 = z_20_0.square_n(20).mul(&z_20_0);
        let z_50_0 = z_40_0.square_n(10).mul(&z_10_0);
        let z_100_0 = z_50_0.square_n(50).mul(&z_50_0);
        let z_200_0 = z_100_0.square_n(100).mul(&z_100_0);
        z_200_0.square_n(50).mul(&z_50_0).square_n(5).mul(&z11)
    }
}

// --- group arithmetic ----------------------------------------------------

/// A point in extended coordinates `(X:Y:Z:T)` with `T = XY/Z`.
#[derive(Clone, Copy)]
pub(crate) struct Ext {
    pub(crate) x: Fe,
    pub(crate) y: Fe,
    pub(crate) z: Fe,
    pub(crate) t: Fe,
}

/// The basepoint precomputed for mixed addition: `(y+x, y-x, 2d·xy)`.
pub(crate) struct Niels {
    y_plus_x: Fe,
    y_minus_x: Fe,
    k: Fe,
}

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("constant is valid hex");
    }
    out
}

impl Niels {
    /// The ed25519 basepoint, precomputed. Coordinates are the RFC 8032
    /// constants, little-endian.
    pub(crate) fn basepoint() -> Niels {
        let x = Fe::from_bytes(&hex32(
            "1ad5258f602d56c9b2a7259560c72c695cdcd6fd31e2a4c0fe536ecdd3366921",
        ));
        let y = Fe::from_bytes(&hex32(
            "5866666666666666666666666666666666666666666666666666666666666666",
        ));
        let d = Fe::from_bytes(&hex32(
            "a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352",
        ));
        Niels {
            y_plus_x: y.add(&x),
            y_minus_x: y.sub(&x),
            k: d.add(&d).mul(&x).mul(&y),
        }
    }
}

impl Ext {
    pub(crate) const IDENTITY: Ext = Ext {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    /// `self + B` (mixed addition, `add-2008-hwcd-3` with a = -1): 8
    /// multiplications. Complete on ed25519, whose `d` is a non-square, so the
    /// identity and repeated points need no special case.
    #[inline(always)]
    pub(crate) fn add_base(&self, base: &Niels) -> Ext {
        let a = self.y.sub(&self.x).mul(&base.y_minus_x);
        let b = self.y.add(&self.x).mul(&base.y_plus_x);
        let c = base.k.mul(&self.t);
        let d = self.z.add(&self.z);
        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);
        Ext {
            x: e.mul(&f),
            y: g.mul(&h),
            t: e.mul(&h),
            z: f.mul(&g),
        }
    }

    /// `2 * self` (`dbl-2008-hwcd`): 4 squarings + 4 multiplications.
    pub(crate) fn double(&self) -> Ext {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square();
        let c = c.add(&c);
        let d = a.negate();
        let e = self.x.add(&self.y).square().sub(&a).sub(&b);
        let g = d.add(&b);
        let f = g.sub(&c);
        let h = d.sub(&b);
        Ext {
            x: e.mul(&f),
            y: g.mul(&h),
            t: e.mul(&h),
            z: f.mul(&g),
        }
    }

    /// `scalar * B` by double-and-add over the fixed basepoint. Used once per
    /// worker to place the start of its walk; the walk itself never needs a
    /// general multiplication.
    pub(crate) fn mul_base(scalar: &Scalar) -> Ext {
        let base = Niels::basepoint();
        let bytes = scalar.to_bytes();
        let mut acc = Ext::IDENTITY;
        for bit in (0..256).rev() {
            acc = acc.double();
            if bytes[bit / 8] >> (bit % 8) & 1 == 1 {
                acc = acc.add_base(&base);
            }
        }
        acc
    }

    /// The compressed encoding, given `1/Z` from a batched inversion.
    pub(crate) fn compress_with(&self, z_inv: &Fe) -> [u8; 32] {
        let mut out = self.y.mul(z_inv).to_bytes();
        out[31] |= (self.x.mul(z_inv).to_bytes()[0] & 1) << 7;
        out
    }
}

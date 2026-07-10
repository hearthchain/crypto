//! BLS12-381 key derivation per EIP-2333 (key generation) and EIP-2334 (paths)
//! — the BLS analog of SLIP-0010. Only derivation is implemented: pure
//! HKDF-SHA-256 + SHA-256 + mod r, no pairing library.
//!
//! Unlike SLIP-0010, EIP-2333 has no hardened/non-hardened distinction: every
//! child is derived from the parent secret key (hardened-equivalent), so paths
//! carry no `'` marker.

use num_bigint::BigUint;
use num_traits::Zero;

use crate::Error;
use crate::primitives::{hmac_sha256, sha256};

/// EIP-2334 purpose (the curve id).
pub const PURPOSE: u32 = 12381;

const LAMPORT_CHUNKS: usize = 255;
const SHA256_LEN: usize = 32;

fn order_r() -> BigUint {
    BigUint::parse_bytes(
        b"52435875175126190479447740508185965837690552500527637822603658699938581184513",
        10,
    )
    .expect("valid decimal")
}

/// Master secret key from a seed (>= 32 bytes). Returns a 32-byte big-endian scalar.
pub fn derive_master_sk(seed: &[u8]) -> Result<[u8; 32], Error> {
    if seed.len() < 32 {
        return Err(Error::Length("EIP-2333 seed must be at least 32 bytes"));
    }
    Ok(hkdf_mod_r(seed, &[]))
}

/// One child derivation step. `index` is a uint32.
pub fn derive_child_sk(parent_sk: &[u8], index: u32) -> [u8; 32] {
    hkdf_mod_r(&parent_sk_to_lamport_pk(parent_sk, index), &[])
}

/// Derive along an EIP-2334 path such as `m/12381/9381/0/0`.
pub fn derive_path(seed: &[u8], path: &str) -> Result<[u8; 32], Error> {
    let mut sk = derive_master_sk(seed)?;
    for index in parse_path(path)? {
        sk = derive_child_sk(&sk, index);
    }
    Ok(sk)
}

pub fn parse_path(path: &str) -> Result<Vec<u32>, Error> {
    let trimmed = path.trim();
    if trimmed != "m" && !trimmed.starts_with("m/") {
        return Err(Error::Path(format!("path must start with 'm': {path}")));
    }
    if trimmed == "m" {
        return Ok(vec![]);
    }
    trimmed[2..]
        .split('/')
        .map(|raw| {
            if raw.contains('\'') {
                return Err(Error::Path(format!(
                    "BLS (EIP-2333) has no hardened notation; drop the ' in '{raw}'"
                )));
            }
            raw.parse::<u32>()
                .map_err(|_| Error::Path(format!("index out of uint32 range: {raw}")))
        })
        .collect()
}

// --- EIP-2333 internals --------------------------------------------------

fn hkdf_mod_r(ikm: &[u8], key_info: &[u8]) -> [u8; 32] {
    const L: usize = 48; // ceil((3 * ceil(log2(r))) / 16)
    let r = order_r();
    let mut salt = b"BLS-SIG-KEYGEN-SALT-".to_vec();
    loop {
        salt = sha256(&salt).to_vec();
        let mut extract_input = ikm.to_vec();
        extract_input.push(0x00); // HKDF-Extract(salt, IKM || I2OSP(0,1))
        let prk = hmac_sha256(&salt, &extract_input);
        let mut info = key_info.to_vec();
        info.extend_from_slice(&[(L >> 8) as u8, L as u8]);
        let okm = hkdf_expand(&prk, &info, L);
        let sk = BigUint::from_bytes_be(&okm) % &r;
        if !sk.is_zero() {
            return left_pad_32(&sk.to_bytes_be());
        }
    }
}

fn parent_sk_to_lamport_pk(parent_sk: &[u8], index: u32) -> [u8; 32] {
    let salt = index.to_be_bytes();
    let ikm = left_pad_32(parent_sk);
    let not_ikm: [u8; 32] = core::array::from_fn(|i| !ikm[i]);
    let mut buf = Vec::with_capacity(2 * LAMPORT_CHUNKS * SHA256_LEN);
    for chunk in ikm_to_lamport_sk(&salt, &ikm) {
        buf.extend_from_slice(&sha256(&chunk));
    }
    for chunk in ikm_to_lamport_sk(&salt, &not_ikm) {
        buf.extend_from_slice(&sha256(&chunk));
    }
    sha256(&buf)
}

fn ikm_to_lamport_sk(salt: &[u8], ikm: &[u8]) -> Vec<[u8; 32]> {
    let prk = hmac_sha256(salt, ikm);
    let okm = hkdf_expand(&prk, &[], LAMPORT_CHUNKS * SHA256_LEN);
    okm.chunks(SHA256_LEN)
        .map(|c| {
            let mut a = [0u8; 32];
            a.copy_from_slice(c);
            a
        })
        .collect()
}

/// HKDF-Expand (RFC 5869) with HMAC-SHA-256. `length` must be <= 255*32.
fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length);
    let mut t: Vec<u8> = Vec::new();
    let mut counter: u16 = 1; // wider than the u8 wire byte so `+= 1` past 255 can't overflow
    while out.len() < length {
        let mut input = t.clone();
        input.extend_from_slice(info);
        input.push(counter as u8);
        t = hmac_sha256(prk, &input).to_vec();
        out.extend_from_slice(&t);
        counter += 1;
    }
    out.truncate(length);
    out
}

fn left_pad_32(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(b);
    out
}

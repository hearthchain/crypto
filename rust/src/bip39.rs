//! BIP-39 mnemonic validation and seed derivation. The seed derivation
//! (PBKDF2-HMAC-SHA512, 2048 iterations) is built on [`crate::primitives`].

use std::collections::HashMap;
use std::sync::LazyLock;

use unicode_normalization::UnicodeNormalization;

use crate::Error;
use crate::primitives::{hmac_sha512, sha256};

const WORDLIST_RAW: &str = include_str!("english.txt");

static WORDLIST: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| WORDLIST_RAW.split_whitespace().collect());

static WORD_INDEX: LazyLock<HashMap<&'static str, usize>> =
    LazyLock::new(|| WORDLIST.iter().enumerate().map(|(i, &w)| (w, i)).collect());

fn normalize(s: &str) -> String {
    s.nfkd().collect()
}

/// Validate the BIP-39 checksum. `Ok(())` if valid, else `Err` with the reason.
pub fn validate(mnemonic: &str) -> Result<(), Error> {
    let normalized = normalize(mnemonic);
    let words: Vec<&str> = normalized.split_whitespace().collect();
    let n = words.len();
    if ![12, 15, 18, 21, 24].contains(&n) {
        return Err(Error::Mnemonic(format!(
            "word count must be 12/15/18/21/24, got {n}"
        )));
    }
    let mut indices = Vec::with_capacity(n);
    for w in &words {
        match WORD_INDEX.get(*w) {
            Some(&idx) => indices.push(idx),
            None => return Err(Error::Mnemonic(format!("unknown word: '{w}'"))),
        }
    }

    let total_bits = n * 11;
    let checksum_bits = total_bits / 33;
    let entropy_bits = total_bits - checksum_bits;
    let mut bits = Vec::with_capacity(total_bits);
    for &idx in &indices {
        for b in (0..11).rev() {
            bits.push(((idx >> b) & 1) as u8);
        }
    }
    let entropy = bits_to_bytes(&bits[..entropy_bits]);
    let hash = sha256(&entropy);
    for i in 0..checksum_bits {
        let expected = (hash[i / 8] >> (7 - (i % 8))) & 1;
        if bits[entropy_bits + i] != expected {
            return Err(Error::Mnemonic("checksum mismatch".to_string()));
        }
    }
    Ok(())
}

/// Derive the 64-byte BIP-39 seed from a mnemonic and optional passphrase.
pub fn to_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    let password = normalize(mnemonic).into_bytes();
    let salt = normalize(&format!("mnemonic{passphrase}")).into_bytes();
    pbkdf2_hmac_sha512(&password, &salt, 2048)
}

fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
    bits.chunks(8)
        .map(|c| c.iter().fold(0u8, |acc, &b| (acc << 1) | b))
        .collect()
}

/// PBKDF2 with PRF = HMAC-SHA512. dkLen = 64 = hLen, so a single block.
fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 64] {
    let mut block = salt.to_vec();
    block.extend_from_slice(&1u32.to_be_bytes()); // INT(1)
    let mut u = hmac_sha512(password, &block);
    let mut t = u;
    for _ in 1..iterations {
        u = hmac_sha512(password, &u);
        for j in 0..64 {
            t[j] ^= u[j];
        }
    }
    t
}

#[cfg(test)]
mod tests {
    use super::WORDLIST_RAW;
    use sha2::{Digest, Sha256};

    /// Guard against drift: the embedded wordlist must be the official BIP-39
    /// English file (its SHA-256 is fixed by the standard).
    #[test]
    fn wordlist_matches_official_bip39() {
        let digest = Sha256::digest(WORDLIST_RAW.as_bytes());
        assert_eq!(
            crate::hex::encode(&digest),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
    }
}

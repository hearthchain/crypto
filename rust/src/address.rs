//! A network-independent account identity: `SHA-256(publicKey)[0:20]`.
//!
//! These 20 bytes ([`Address::to_bytes`]) are the canonical on-chain id — the
//! transaction recipient field, state keys, and equality all use them. The
//! **network is not part of the identity**; it only selects the human-readable
//! prefix (HRP) when rendering or parsing the bech32m string, so the HRP is
//! supplied at that boundary rather than stored here. The same account on any
//! network is one `Address`.

use crate::Error;
use crate::bech32m;
use crate::primitives::sha256;

/// Canonical bech32m prefix for mainnet.
pub const MAINNET_HRP: &str = "hrth";
/// Canonical bech32m prefix for testnet.
pub const TESTNET_HRP: &str = "thrth";

/// Length of the account hash, in bytes.
pub const HASH_LEN: usize = 20;

/// An account address: the 20-byte hash, with no network attached.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Address {
    hash: [u8; HASH_LEN],
}

impl Address {
    /// Derive the address for an Ed25519 public key.
    pub fn from_public_key(public_key: &[u8]) -> Result<Address, Error> {
        if public_key.len() != 32 {
            return Err(Error::Length("public key must be 32 bytes"));
        }
        let mut hash = [0u8; HASH_LEN];
        hash.copy_from_slice(&sha256(public_key)[..HASH_LEN]);
        Ok(Address { hash })
    }

    /// Parse the raw 20-byte on-chain form, e.g. a transaction's recipient
    /// field. `None` if the payload is the wrong length.
    pub fn from_bytes(payload: &[u8]) -> Option<Address> {
        Some(Address {
            hash: payload.try_into().ok()?,
        })
    }

    /// Parse a bech32m string, requiring its HRP to equal `hrp`.
    pub fn parse(s: &str, hrp: &str) -> Option<Address> {
        let want = normalize_hrp(hrp)?;
        let (got, payload) = bech32m::decode(s)?;
        if got != want {
            return None;
        }
        Address::from_bytes(&payload)
    }

    /// The HRP a bech32m address string is encoded for, if it decodes at all.
    pub fn hrp_of(s: &str) -> Option<String> {
        bech32m::decode(s).map(|(hrp, _)| hrp)
    }

    /// The canonical 20-byte on-chain form.
    pub fn to_bytes(&self) -> [u8; HASH_LEN] {
        self.hash
    }

    /// The bech32m address string under the given HRP.
    ///
    /// # Panics
    /// If `hrp` is not a valid lowercase bech32 prefix.
    pub fn to_bech32(&self, hrp: &str) -> String {
        let hrp = normalize_hrp(hrp).expect("HRP must be 1..=83 lowercase a-z characters");
        bech32m::encode(&hrp, &self.hash)
    }
}

/// Whether `hrp` is a usable bech32 prefix: 1..=83 lowercase ASCII letters.
pub fn valid_hrp(hrp: &str) -> bool {
    normalize_hrp(hrp).is_some()
}

/// Validate a bech32 HRP, returning it owned. `None` if malformed.
fn normalize_hrp(hrp: &str) -> Option<String> {
    if hrp.is_empty() || hrp.len() > 83 || !hrp.bytes().all(|c| c.is_ascii_lowercase()) {
        return None;
    }
    Some(hrp.to_string())
}

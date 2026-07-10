//! The three role keys, derived from one BIP-39 seed at separate paths. Signing
//! and VRF keys use different hardened SLIP-0010 role indices so their secret
//! scalars are unrelated — removing the EdDSA/ECVRF shared-key risk. BLS finality
//! keys live in their own EIP-2333 tree (different curve).

use crate::ed25519::KeyPair;
use crate::{Error, bls, ed25519, slip10};

const COIN_TYPE: u32 = 9381; // placeholder — register a SLIP-0044 value
const ROLE_SIGNING: u32 = 0;
const ROLE_VRF: u32 = 1;

pub fn signing_path(account: u32) -> String {
    format!("m/44'/{COIN_TYPE}'/{account}'/{ROLE_SIGNING}'/0'")
}

pub fn vrf_path(account: u32) -> String {
    format!("m/44'/{COIN_TYPE}'/{account}'/{ROLE_VRF}'/0'")
}

pub fn bls_path(account: u32) -> String {
    format!("m/{}/{COIN_TYPE}/{account}/0", bls::PURPOSE)
}

/// ed25519 keypair for signing transactions.
pub fn signing_key(seed: &[u8], account: u32) -> Result<KeyPair, Error> {
    ed25519::KeyPair::from_seed(&slip10::derive_path(seed, &signing_path(account))?.private_key)
}

/// ed25519 keypair for the VRF (its `seed` feeds [`crate::ecvrf::prove`]).
pub fn vrf_key(seed: &[u8], account: u32) -> Result<KeyPair, Error> {
    ed25519::KeyPair::from_seed(&slip10::derive_path(seed, &vrf_path(account))?.private_key)
}

/// BLS12-381 finality secret key (32-byte big-endian scalar).
pub fn bls_secret_key(seed: &[u8], account: u32) -> Result<[u8; 32], Error> {
    bls::derive_path(seed, &bls_path(account))
}

//! hearth-chain crypto foundation (pure Rust): Ed25519 signatures, ECVRF
//! (RFC 9381), and BLS12-381 key derivation, all from a single BIP-39 mnemonic.
//!
//! Curve/hash primitives use `curve25519-dalek`, `ed25519-dalek`, and the
//! RustCrypto `sha2`/`hmac` crates — audited, constant-time, no C dependency.

pub mod address;
pub mod bech32m;
pub mod bip39;
pub mod bls;
pub mod ecvrf;
pub mod ed25519;
pub mod hex;
pub mod keytree;
pub mod primitives;
pub mod slip10;

/// Errors returned by fallible operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A mnemonic failed BIP-39 validation; carries the reason.
    Mnemonic(String),
    /// A derivation path was malformed; carries the reason.
    Path(String),
    /// An input had the wrong length.
    Length(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Mnemonic(m) | Error::Path(m) => write!(f, "{m}"),
            Error::Length(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {}

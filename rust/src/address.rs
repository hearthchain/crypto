//! Account addresses: `Bech32m(hrp, versionByte || SHA-256(publicKey)[0:20])`.
//! The per-network HRP is a UX guard against sending to the wrong network; it is
//! not replay protection (that belongs in the signed transaction).

use crate::Error;
use crate::bech32m;
use crate::primitives::sha256;

const ED25519_VERSION: u8 = 0x00;
const HASH_LEN: usize = 20;

/// Address network.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Network {
    Testnet,
    Mainnet,
}

impl Network {
    pub fn hrp(self) -> &'static str {
        match self {
            Network::Testnet => "hrtht",
            Network::Mainnet => "hrthm",
        }
    }

    fn by_hrp(hrp: &str) -> Option<Network> {
        match hrp {
            "hrtht" => Some(Network::Testnet),
            "hrthm" => Some(Network::Mainnet),
            _ => None,
        }
    }
}

/// A decoded address.
#[derive(Clone, Debug)]
pub struct Address {
    pub network: Network,
    pub hash: Vec<u8>,
    pub version: u8,
}

/// Derive the address string for an Ed25519 public key on a given network.
pub fn from_public_key(public_key: &[u8], network: Network) -> Result<String, Error> {
    if public_key.len() != 32 {
        return Err(Error::Length("public key must be 32 bytes"));
    }
    let mut payload = Vec::with_capacity(1 + HASH_LEN);
    payload.push(ED25519_VERSION);
    payload.extend_from_slice(&sha256(public_key)[..HASH_LEN]);
    Ok(bech32m::encode(network.hrp(), &payload))
}

/// Parse and validate an address string.
pub fn parse(s: &str) -> Option<Address> {
    let (hrp, payload) = bech32m::decode(s)?;
    let network = Network::by_hrp(&hrp)?;
    if payload.len() != HASH_LEN + 1 || payload[0] != ED25519_VERSION {
        return None;
    }
    Some(Address {
        network,
        hash: payload[1..].to_vec(),
        version: payload[0],
    })
}

/// Parse and require a specific network (rejects cross-network addresses).
pub fn parse_for(s: &str, expected: Network) -> Option<Address> {
    parse(s).filter(|a| a.network == expected)
}

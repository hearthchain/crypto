//! SLIP-0010 hierarchical derivation for the ed25519 curve (hardened-only) —
//! the derivation Ledger uses for Ed25519 accounts.

use crate::Error;
use crate::primitives::hmac_sha512;

const HARDENED: u32 = 0x8000_0000;

/// A SLIP-0010 node.
#[derive(Clone)]
pub struct Node {
    pub private_key: [u8; 32],
    pub chain_code: [u8; 32],
}

/// Master node from a BIP-39 (or any) seed.
pub fn master(seed: &[u8]) -> Node {
    split(hmac_sha512(b"ed25519 seed", seed))
}

/// One hardened child step (the hardened bit is added automatically).
pub fn derive_child(parent: &Node, index: u32) -> Node {
    let hardened = index | HARDENED;
    let mut data = Vec::with_capacity(1 + 32 + 4);
    data.push(0u8);
    data.extend_from_slice(&parent.private_key);
    data.extend_from_slice(&hardened.to_be_bytes());
    split(hmac_sha512(&parent.chain_code, &data))
}

/// Derive along a path such as `m/44'/9381'/0'/0'/0'`. Every level is hardened.
pub fn derive_path(seed: &[u8], path: &str) -> Result<Node, Error> {
    let mut node = master(seed);
    for index in parse_path(path)? {
        node = derive_child(&node, index);
    }
    Ok(node)
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
            let cleaned = raw.trim_end_matches(['\'', 'h', 'H']);
            let n: u64 = cleaned
                .parse()
                .map_err(|_| Error::Path(format!("bad path segment: '{raw}'")))?;
            if n >= HARDENED as u64 {
                return Err(Error::Path(format!("index out of range: {raw}")));
            }
            Ok(n as u32)
        })
        .collect()
}

fn split(i: [u8; 64]) -> Node {
    let mut private_key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    private_key.copy_from_slice(&i[..32]);
    chain_code.copy_from_slice(&i[32..]);
    Node {
        private_key,
        chain_code,
    }
}

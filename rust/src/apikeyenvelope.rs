//! The wire format for handing an API key to a recipient that published an
//! X25519 public key — typically a confidential VM (Intel TDX) that generated
//! the key inside the TD and bound it into its attestation report.
//!
//! The envelope is a thin, self-describing frame around [`crate::hpke`]:
//!
//! ```text
//!   offset size field
//!   0      4    "HKE1"                      format magic and version
//!   4      2    kem_id                      0x0020, DHKEM(X25519, HKDF-SHA256)
//!   6      2    kdf_id                      0x0001, HKDF-SHA256
//!   8      2    aead_id                     0x0003 by default, ChaCha20-Poly1305
//!   10     8    fingerprint                 SHA-256(recipient public key)[0..8]
//!   18     2    metadata_len
//!   20     m    metadata                    key id and expiry, see `Metadata`
//!   20+m   32   enc                         the encapsulated key
//!   52+m   48   ciphertext                  32-byte API key + 16-byte tag
//! ```
//!
//! Everything before `enc` is passed to the AEAD as additional authenticated
//! data, so the suite ids, the recipient fingerprint and the metadata are all
//! covered by the tag: an envelope cannot be re-labelled with a different key
//! id or expiry, and the `info` string pins it to this protocol so it cannot
//! be replayed into another one.
//!
//! **What this does not give you.** HPKE base mode does not authenticate the
//! sender, and an envelope stays decryptable as long as the recipient's
//! private key lives: authorize the delivery request at the transport layer,
//! keep the recipient keypair ephemeral per boot, and set an expiry. And none
//! of it means anything until the caller has verified the attestation quote
//! and checked that the recipient's public key is the one bound into
//! `REPORTDATA`.

use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;
use rand::rngs::OsRng;

use crate::Error;
use crate::hpke::{self, ENC_BYTES, Suite, TAG_BYTES};
use crate::primitives::sha256;
use crate::x25519;

/// API keys are exactly this many characters.
pub const API_KEY_LENGTH: usize = 32;

/// ChaCha20-Poly1305: no reliance on the TD having usable AES-NI.
pub const DEFAULT_SUITE: Suite = Suite::X25519Sha256ChaCha20Poly1305;

/// Bytes of SHA-256(public key) carried in the header.
pub const FINGERPRINT_BYTES: usize = 8;

/// The HPKE `info` string. Changing it breaks compatibility, by design.
const INFO: &[u8] = b"hearth-chain/api-key-hpke/v1";

const MAGIC: &[u8; 4] = b"HKE1";
const HEADER_FIXED_BYTES: usize = 20;
const MAX_METADATA_BYTES: usize = 0xffff;

const ALPHANUMERIC: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
/// Largest multiple of 62 that fits in a byte; above it, resample (no modulo bias).
const SAMPLE_LIMIT: u32 = (256 / ALPHANUMERIC.len() as u32) * ALPHANUMERIC.len() as u32;

/// What the envelope claims about the key it carries, authenticated by the
/// AEAD tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    /// An identifier for the API key, 1..255 bytes of UTF-8; it lets the
    /// recipient tell which key it received without logging the key itself.
    pub key_id: String,
    /// When the key stops being valid, or `None` for no expiry. Truncated to
    /// whole seconds on the wire.
    pub not_after: Option<SystemTime>,
}

impl Metadata {
    /// Metadata with no expiry.
    pub fn new(key_id: impl Into<String>) -> Result<Metadata, Error> {
        Metadata::with_expiry(key_id, None)
    }

    /// Metadata that expires at `not_after`.
    pub fn with_expiry(
        key_id: impl Into<String>,
        not_after: Option<SystemTime>,
    ) -> Result<Metadata, Error> {
        let key_id = key_id.into();
        let length = key_id.len();
        if !(1..=255).contains(&length) {
            return Err(Error::Crypto(format!(
                "key id must be 1..255 bytes of UTF-8, was {length}"
            )));
        }
        Ok(Metadata { key_id, not_after })
    }

    fn encode(&self) -> Vec<u8> {
        let id = self.key_id.as_bytes();
        let epoch_seconds = self.not_after.map_or(0, |t| {
            t.duration_since(UNIX_EPOCH)
                .expect("not_after must be after the epoch")
                .as_secs()
        });
        let mut out = Vec::with_capacity(1 + id.len() + 8);
        out.push(id.len() as u8);
        out.extend_from_slice(id);
        out.extend_from_slice(&epoch_seconds.to_be_bytes());
        out
    }

    fn decode(encoded: &[u8]) -> Result<Metadata, Error> {
        if encoded.len() < 1 + 8 {
            return Err(Error::Crypto("truncated envelope metadata".to_string()));
        }
        let length = encoded[0] as usize;
        if encoded.len() != 1 + length + 8 {
            return Err(Error::Crypto(
                "envelope metadata length mismatch".to_string(),
            ));
        }
        let id = String::from_utf8(encoded[1..1 + length].to_vec()).map_err(|_| {
            Error::Crypto("envelope metadata key id is not valid UTF-8".to_string())
        })?;
        let mut epoch_bytes = [0u8; 8];
        epoch_bytes.copy_from_slice(&encoded[1 + length..1 + length + 8]);
        let epoch_seconds = u64::from_be_bytes(epoch_bytes);
        let not_after = if epoch_seconds == 0 {
            None
        } else {
            Some(UNIX_EPOCH + std::time::Duration::from_secs(epoch_seconds))
        };
        Ok(Metadata {
            key_id: id,
            not_after,
        })
    }
}

/// A decrypted envelope. Call [`Opened::wipe`] once the key has been used —
/// the point of returning `Vec<u8>` of ASCII bytes rather than `String` is
/// that it can be zeroed in place, which `String` makes awkward.
#[derive(Debug)]
pub struct Opened {
    pub api_key: Vec<u8>,
    pub metadata: Metadata,
}

impl Opened {
    pub fn wipe(&mut self) {
        self.api_key.iter_mut().for_each(|b| *b = 0);
    }

    /// The API key as a `str`. Valid as long as the bytes are ASCII
    /// alphanumeric, which `open` has already checked.
    pub fn api_key_str(&self) -> &str {
        std::str::from_utf8(&self.api_key).expect("validated alphanumeric ASCII")
    }
}

/// Seal an API key to `recipient_public_key` with the default suite.
///
/// The caller must already have verified that this public key belongs to the
/// enclave it expects; this function cannot check that.
///
/// Returns [`Error::Crypto`] if the API key is not [`API_KEY_LENGTH`]
/// alphanumeric characters.
pub fn seal(
    recipient_public_key: &[u8; ENC_BYTES],
    api_key: &[u8],
    metadata: &Metadata,
) -> Result<Vec<u8>, Error> {
    seal_with_suite(recipient_public_key, api_key, metadata, DEFAULT_SUITE)
}

/// Seal an API key with an explicit suite.
pub fn seal_with_suite(
    recipient_public_key: &[u8; ENC_BYTES],
    api_key: &[u8],
    metadata: &Metadata,
    suite: Suite,
) -> Result<Vec<u8>, Error> {
    validate_api_key(api_key)?;
    let header = header(
        suite,
        &fingerprint(recipient_public_key),
        &metadata.encode(),
    )?;
    let sealed = hpke::seal(suite, recipient_public_key, INFO, &header, api_key)?;
    let mut envelope = Vec::with_capacity(header.len() + ENC_BYTES + sealed.ciphertext.len());
    envelope.extend_from_slice(&header);
    envelope.extend_from_slice(&sealed.enc);
    envelope.extend_from_slice(&sealed.ciphertext);
    Ok(envelope)
}

/// Open an envelope, rejecting one that has expired as of `now`.
///
/// Returns [`Error::Crypto`] if the envelope is malformed, sealed to a
/// different recipient key, not authentic, or expired.
pub fn open(
    recipient_secret_key: &[u8; ENC_BYTES],
    envelope: &[u8],
    now: SystemTime,
) -> Result<Opened, Error> {
    if envelope.len() < HEADER_FIXED_BYTES {
        return Err(Error::Crypto("truncated envelope".to_string()));
    }
    if &envelope[0..4] != MAGIC {
        return Err(Error::Crypto("not an API key envelope".to_string()));
    }
    let kem_id = u16::from_be_bytes([envelope[4], envelope[5]]);
    let kdf_id = u16::from_be_bytes([envelope[6], envelope[7]]);
    let aead_id = u16::from_be_bytes([envelope[8], envelope[9]]);
    if kem_id != hpke::KEM_ID || kdf_id != hpke::KDF_ID {
        return Err(Error::Crypto(format!(
            "unsupported HPKE suite: kem=0x{kem_id:04x} kdf=0x{kdf_id:04x}"
        )));
    }
    let suite = Suite::from_aead_id(aead_id)?;

    let fingerprint_bytes = &envelope[10..10 + FINGERPRINT_BYTES];
    let metadata_length = u16::from_be_bytes([envelope[18], envelope[19]]) as usize;

    let ciphertext_length = API_KEY_LENGTH + TAG_BYTES;
    let expected = HEADER_FIXED_BYTES + metadata_length + ENC_BYTES + ciphertext_length;
    if envelope.len() != expected {
        return Err(Error::Crypto(format!(
            "envelope length mismatch: expected {expected} bytes, got {}",
            envelope.len()
        )));
    }
    let metadata_bytes = &envelope[HEADER_FIXED_BYTES..HEADER_FIXED_BYTES + metadata_length];
    let enc_offset = HEADER_FIXED_BYTES + metadata_length;
    let mut enc = [0u8; ENC_BYTES];
    enc.copy_from_slice(&envelope[enc_offset..enc_offset + ENC_BYTES]);
    let ciphertext = &envelope[enc_offset + ENC_BYTES..];

    let recipient_public_key = x25519::public_key(recipient_secret_key);
    if fingerprint_bytes != fingerprint(&recipient_public_key) {
        return Err(Error::Crypto(
            "envelope is sealed to a different recipient key".to_string(),
        ));
    }

    // Everything before enc is the AAD, so the suite ids, fingerprint and
    // metadata are all covered by the tag.
    let header = &envelope[..HEADER_FIXED_BYTES + metadata_length];
    let mut plaintext = hpke::open(suite, recipient_secret_key, &enc, INFO, header, ciphertext)?;

    let result = (|| -> Result<Opened, Error> {
        validate_api_key(&plaintext)?;
        let metadata = Metadata::decode(metadata_bytes)?;
        if let Some(not_after) = metadata.not_after
            && now >= not_after
        {
            let epoch = not_after
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            return Err(Error::Crypto(format!(
                "envelope expired at epoch second {epoch}"
            )));
        }
        Ok(Opened {
            api_key: plaintext.clone(),
            metadata,
        })
    })();
    plaintext.iter_mut().for_each(|b| *b = 0);
    result
}

/// SHA-256(public key) truncated to [`FINGERPRINT_BYTES`] bytes.
pub fn fingerprint(public_key: &[u8; ENC_BYTES]) -> [u8; FINGERPRINT_BYTES] {
    let mut out = [0u8; FINGERPRINT_BYTES];
    out.copy_from_slice(&sha256(public_key)[..FINGERPRINT_BYTES]);
    out
}

/// A fresh [`API_KEY_LENGTH`]-character alphanumeric API key, uniform over
/// the 62-character alphabet (rejection sampling — `% 62` on a random byte
/// would favour the first 8 characters).
pub fn random_api_key() -> Vec<u8> {
    let mut key = Vec::with_capacity(API_KEY_LENGTH);
    let mut buffer = [0u8; API_KEY_LENGTH];
    while key.len() < API_KEY_LENGTH {
        OsRng.fill_bytes(&mut buffer);
        for &sample in buffer.iter() {
            if key.len() == API_KEY_LENGTH {
                break;
            }
            if (sample as u32) < SAMPLE_LIMIT {
                key.push(ALPHANUMERIC[sample as usize % ALPHANUMERIC.len()]);
            }
        }
    }
    key
}

fn header(
    suite: Suite,
    fingerprint: &[u8; FINGERPRINT_BYTES],
    metadata: &[u8],
) -> Result<Vec<u8>, Error> {
    if metadata.len() > MAX_METADATA_BYTES {
        return Err(Error::Crypto(format!(
            "envelope metadata too long: {}",
            metadata.len()
        )));
    }
    let mut out = Vec::with_capacity(HEADER_FIXED_BYTES + metadata.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&hpke::KEM_ID.to_be_bytes());
    out.extend_from_slice(&hpke::KDF_ID.to_be_bytes());
    out.extend_from_slice(&suite.aead_id().to_be_bytes());
    out.extend_from_slice(fingerprint);
    out.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
    out.extend_from_slice(metadata);
    Ok(out)
}

fn validate_api_key(api_key: &[u8]) -> Result<(), Error> {
    if api_key.len() != API_KEY_LENGTH {
        return Err(Error::Crypto(format!(
            "API key must be {API_KEY_LENGTH} characters"
        )));
    }
    if !api_key.iter().all(|&b| b.is_ascii_alphanumeric()) {
        return Err(Error::Crypto("API key must be alphanumeric".to_string()));
    }
    Ok(())
}

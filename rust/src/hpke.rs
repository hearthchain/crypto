//! HPKE (RFC 9180) single-shot public-key encryption, base mode, over
//! **DHKEM(X25519, HKDF-SHA256)** + **HKDF-SHA256**.
//!
//! Base mode means the sender is anonymous: anyone holding the recipient's
//! public key can seal. That is exactly the shape of "encrypt a secret to a
//! public key published by an enclave" — the recipient is authenticated (by
//! attestation, out of band), the sender is authorized by the transport.
//!
//! Only the single-shot `Seal`/`Open` of RFC 9180 §6.1 is implemented — one
//! message per encapsulation, always at sequence number 0. There is
//! deliberately no stateful sender context to reuse, so a nonce can never be
//! repeated under one key.
//!
//! HMAC-SHA256 comes from [`crate::primitives::hmac_sha256`], the AEADs from
//! the RustCrypto `aes-gcm`/`chacha20poly1305` crates, and the group
//! operation from [`crate::x25519`]. Verified against the RFC 9180 A.1 and
//! A.2 test vectors.
//!
//! See [`crate::apikeyenvelope`] for the ready-made wire format this library
//! uses for shipping an API key to an enclave.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;

use crate::Error;
use crate::primitives::hmac_sha256;
use crate::x25519::{self, KEY_BYTES as X25519_KEY_BYTES};

/// DHKEM(X25519, HKDF-SHA256).
pub const KEM_ID: u16 = 0x0020;
/// HKDF-SHA256.
pub const KDF_ID: u16 = 0x0001;
/// Size of an encapsulated key (a serialized X25519 public key).
pub const ENC_BYTES: usize = X25519_KEY_BYTES;
/// Every AEAD here has a 16-byte tag.
pub const TAG_BYTES: usize = 16;

const MODE_BASE: u8 = 0x00;
const NH: usize = 32; // Nh for HKDF-SHA256
const NSECRET: usize = 32; // Nsecret for DHKEM(X25519, ...)

const HPKE_V1: &[u8] = b"HPKE-v1";

/// The supported ciphersuites. All share DHKEM(X25519, HKDF-SHA256) and
/// HKDF-SHA256 and differ only in the AEAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    /// RFC 9180 A.1. The mandatory-to-implement AEAD.
    X25519Sha256Aes128Gcm,
    /// 256-bit AES, for when a key-size policy asks for it.
    X25519Sha256Aes256Gcm,
    /// RFC 9180 A.2. The default here: no AES-NI dependency for constant time.
    X25519Sha256ChaCha20Poly1305,
}

impl Suite {
    /// The RFC 9180 AEAD id.
    pub fn aead_id(self) -> u16 {
        match self {
            Suite::X25519Sha256Aes128Gcm => 0x0001,
            Suite::X25519Sha256Aes256Gcm => 0x0002,
            Suite::X25519Sha256ChaCha20Poly1305 => 0x0003,
        }
    }

    /// AEAD key length, Nk.
    pub fn key_bytes(self) -> usize {
        match self {
            Suite::X25519Sha256Aes128Gcm => 16,
            Suite::X25519Sha256Aes256Gcm => 32,
            Suite::X25519Sha256ChaCha20Poly1305 => 32,
        }
    }

    /// AEAD nonce length, Nn. 12 for every AEAD registered so far.
    pub fn nonce_bytes(self) -> usize {
        12
    }

    /// The suite with this AEAD id.
    pub fn from_aead_id(aead_id: u16) -> Result<Suite, Error> {
        match aead_id {
            0x0001 => Ok(Suite::X25519Sha256Aes128Gcm),
            0x0002 => Ok(Suite::X25519Sha256Aes256Gcm),
            0x0003 => Ok(Suite::X25519Sha256ChaCha20Poly1305),
            _ => Err(Error::Crypto(format!(
                "unsupported HPKE AEAD id: 0x{aead_id:04x}"
            ))),
        }
    }
}

/// The output of `Seal`: the encapsulated key and the ciphertext.
pub struct Sealed {
    pub enc: [u8; ENC_BYTES],
    pub ciphertext: Vec<u8>,
}

/// The key schedule outputs of RFC 9180 §5.1.
pub struct Context {
    pub key: Vec<u8>,
    pub base_nonce: Vec<u8>,
    pub exporter_secret: [u8; NH],
}

/// Encrypt `plaintext` to `recipient_public_key` with a fresh ephemeral key.
///
/// `info` is application context bound into the key schedule; it must be a
/// fixed, purpose-specific string so ciphertexts cannot be replayed into a
/// different protocol. `aad` is authenticated but not encrypted.
pub fn seal(
    suite: Suite,
    recipient_public_key: &[u8; ENC_BYTES],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Sealed, Error> {
    let ephemeral = x25519::generate_keypair();
    seal_with_ephemeral(
        suite,
        &ephemeral.secret_key,
        recipient_public_key,
        info,
        aad,
        plaintext,
    )
}

/// Decrypt.
///
/// Returns [`Error::Crypto`] if authentication fails — a corrupt, forged, or
/// mis-addressed ciphertext is indistinguishable here.
pub fn open(
    suite: Suite,
    recipient_secret_key: &[u8; ENC_BYTES],
    enc: &[u8; ENC_BYTES],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    if ciphertext.len() < TAG_BYTES {
        return Err(Error::Crypto(
            "ciphertext is shorter than the AEAD tag".to_string(),
        ));
    }
    let dh = x25519::dh(recipient_secret_key, enc)?;
    let recipient_public_key = x25519::public_key(recipient_secret_key);
    let shared_secret = extract_and_expand(&dh, enc, &recipient_public_key);
    let context = key_schedule(suite, &shared_secret, info);
    aead_open(suite, &context.key, &context.base_nonce, aad, ciphertext)
}

// ---------------------------------------------------------------- internals

/// `Seal` with a caller-supplied ephemeral key. Public (unlike Java's
/// package-private twin) so the RFC 9180 vectors — which pin `skEm` — can be
/// checked from an integration test; outside a test, reusing an ephemeral key
/// here would repeat the AEAD nonce, so always prefer [`seal`].
pub fn seal_with_ephemeral(
    suite: Suite,
    ephemeral_secret_key: &[u8; ENC_BYTES],
    recipient_public_key: &[u8; ENC_BYTES],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Sealed, Error> {
    let enc = x25519::public_key(ephemeral_secret_key);
    let dh = x25519::dh(ephemeral_secret_key, recipient_public_key)?;
    let shared_secret = extract_and_expand(&dh, &enc, recipient_public_key);
    let context = key_schedule(suite, &shared_secret, info);
    let ciphertext = aead_seal(suite, &context.key, &context.base_nonce, aad, plaintext);
    Ok(Sealed { enc, ciphertext })
}

/// DHKEM's `ExtractAndExpand` (RFC 9180 §4.1), shared by Encap and Decap.
pub fn extract_and_expand(
    dh: &[u8; ENC_BYTES],
    enc: &[u8; ENC_BYTES],
    recipient_public_key: &[u8; ENC_BYTES],
) -> [u8; NSECRET] {
    let kem_suite_id = concat(&[b"KEM", &i2osp(KEM_ID as u32, 2)]);
    let eae_prk = labeled_extract(&kem_suite_id, &[], "eae_prk", dh);
    let kem_context = concat(&[enc.as_slice(), recipient_public_key.as_slice()]);
    let out = labeled_expand(
        &kem_suite_id,
        &eae_prk,
        "shared_secret",
        &kem_context,
        NSECRET,
    );
    let mut fixed = [0u8; NSECRET];
    fixed.copy_from_slice(&out);
    fixed
}

/// `KeySchedule` for mode_base (RFC 9180 §5.1): psk and psk_id are empty.
pub fn key_schedule(suite: Suite, shared_secret: &[u8; NSECRET], info: &[u8]) -> Context {
    let suite_id = suite_id(suite);
    let psk_id_hash = labeled_extract(&suite_id, &[], "psk_id_hash", &[]);
    let info_hash = labeled_extract(&suite_id, &[], "info_hash", info);
    let key_schedule_context =
        concat(&[&[MODE_BASE], psk_id_hash.as_slice(), info_hash.as_slice()]);

    let secret = labeled_extract(&suite_id, shared_secret, "secret", &[]);
    let key = labeled_expand(
        &suite_id,
        &secret,
        "key",
        &key_schedule_context,
        suite.key_bytes(),
    );
    let base_nonce = labeled_expand(
        &suite_id,
        &secret,
        "base_nonce",
        &key_schedule_context,
        suite.nonce_bytes(),
    );
    let exporter_secret = labeled_expand(&suite_id, &secret, "exp", &key_schedule_context, NH);
    let mut exporter_fixed = [0u8; NH];
    exporter_fixed.copy_from_slice(&exporter_secret);
    Context {
        key,
        base_nonce,
        exporter_secret: exporter_fixed,
    }
}

fn suite_id(suite: Suite) -> Vec<u8> {
    concat(&[
        b"HPKE",
        &i2osp(KEM_ID as u32, 2),
        &i2osp(KDF_ID as u32, 2),
        &i2osp(suite.aead_id() as u32, 2),
    ])
}

fn labeled_extract(suite_id: &[u8], salt: &[u8], label: &str, ikm: &[u8]) -> [u8; NH] {
    extract(salt, &concat(&[HPKE_V1, suite_id, label.as_bytes(), ikm]))
}

fn labeled_expand(
    suite_id: &[u8],
    prk: &[u8; NH],
    label: &str,
    info: &[u8],
    length: usize,
) -> Vec<u8> {
    let labeled_info = concat(&[
        &i2osp(length as u32, 2),
        HPKE_V1,
        suite_id,
        label.as_bytes(),
        info,
    ]);
    expand(prk, &labeled_info, length)
}

/// HKDF-Extract (RFC 5869 §2.2). An empty salt becomes HashLen zero bytes, as
/// the RFC specifies — HMAC zero-pads its key, so this is also what an
/// empty-key HMAC would produce, but spelling it out keeps this explicit.
fn extract(salt: &[u8], ikm: &[u8]) -> [u8; NH] {
    if salt.is_empty() {
        hmac_sha256(&[0u8; NH], ikm)
    } else {
        hmac_sha256(salt, ikm)
    }
}

/// HKDF-Expand (RFC 5869 §2.3).
fn expand(prk: &[u8; NH], info: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length);
    let mut block: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while out.len() < length {
        let mut data = block.clone();
        data.extend_from_slice(info);
        data.push(counter);
        block = hmac_sha256(prk, &data).to_vec();
        let take = (length - out.len()).min(block.len());
        out.extend_from_slice(&block[..take]);
        counter += 1;
    }
    out
}

/// One-shot AEAD seal at sequence number 0, where the nonce is the base nonce
/// unchanged (RFC 9180 §5.2 XORs the sequence number in; it is zero here).
fn aead_seal(suite: Suite, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    match suite {
        Suite::X25519Sha256Aes128Gcm => Aes128Gcm::new_from_slice(key)
            .expect("HPKE key length matches suite.key_bytes()")
            .encrypt(nonce.into(), payload)
            .expect("AEAD seal cannot fail"),
        Suite::X25519Sha256Aes256Gcm => Aes256Gcm::new_from_slice(key)
            .expect("HPKE key length matches suite.key_bytes()")
            .encrypt(nonce.into(), payload)
            .expect("AEAD seal cannot fail"),
        Suite::X25519Sha256ChaCha20Poly1305 => ChaCha20Poly1305::new_from_slice(key)
            .expect("HPKE key length matches suite.key_bytes()")
            .encrypt(nonce.into(), payload)
            .expect("AEAD seal cannot fail"),
    }
}

fn aead_open(
    suite: Suite,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    let result = match suite {
        Suite::X25519Sha256Aes128Gcm => Aes128Gcm::new_from_slice(key)
            .expect("HPKE key length matches suite.key_bytes()")
            .decrypt(nonce.into(), payload),
        Suite::X25519Sha256Aes256Gcm => Aes256Gcm::new_from_slice(key)
            .expect("HPKE key length matches suite.key_bytes()")
            .decrypt(nonce.into(), payload),
        Suite::X25519Sha256ChaCha20Poly1305 => ChaCha20Poly1305::new_from_slice(key)
            .expect("HPKE key length matches suite.key_bytes()")
            .decrypt(nonce.into(), payload),
    };
    result.map_err(|_| Error::Crypto("HPKE open failed: ciphertext is not authentic".to_string()))
}

fn i2osp(n: u32, length: usize) -> Vec<u8> {
    n.to_be_bytes()[4 - length..].to_vec()
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

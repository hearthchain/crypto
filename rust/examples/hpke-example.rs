//! Delivering an API key to a confidential VM: the TD publishes an X25519
//! public key bound into its attestation report, the client seals the key to
//! it with HPKE, and only the TD can open it.
//!
//! Usage: `cargo run --example hpke-example`

use std::time::{Duration, SystemTime};

use hearth::apikeyenvelope::{self, Metadata};
use hearth::hex;
use hearth::hpke::{self, Suite};
use hearth::primitives::sha512;
use hearth::x25519;

const REPORT_DATA_CONTEXT: &[u8] = b"hearth-chain/tdx-hpke/v1";

fn section(title: &str) {
    println!("\n== {title} ==");
}

fn failure_of<T>(action: impl FnOnce() -> Result<T, hearth::Error>) -> String {
    match action() {
        Ok(_) => "OPENED — this should not happen".to_string(),
        Err(e) => format!("rejected: {e}"),
    }
}

fn main() {
    section("1) Inside the TD: generate the recipient keypair, bind it to the quote");
    // In a real TD this keypair is generated at boot and never leaves the
    // enclave; the private key is not persisted anywhere.
    let enclave = x25519::generate_keypair();
    let mut report_input = REPORT_DATA_CONTEXT.to_vec();
    report_input.extend_from_slice(&enclave.public_key);
    let report_data = sha512(&report_input);
    println!(
        "public key (X25519, 32 B): {}",
        hex::encode(&enclave.public_key)
    );
    println!("REPORTDATA  (SHA-512, 64 B): {}", hex::encode(&report_data));
    println!("  the TD puts this in its quote; the client recomputes it from the");
    println!("  public key it was handed and compares — that is the binding.");

    section("2) On the client: verify the quote, then seal the API key");
    println!("(quote verification is out of scope here — check the signature chain,");
    println!(" the TCB status, MRTD/RTMR, and that REPORTDATA matches the line above)");

    let api_key = apikeyenvelope::random_api_key();
    let expiry = SystemTime::now() + Duration::from_secs(24 * 3600);
    let metadata = Metadata::with_expiry("prod/ingest-api", Some(expiry)).unwrap();
    let envelope = apikeyenvelope::seal(&enclave.public_key, &api_key, &metadata).unwrap();

    println!("api key      : {}", String::from_utf8_lossy(&api_key));
    println!("key id       : {}", metadata.key_id);
    println!(
        "suite        : ChaCha20-Poly1305 (aead 0x{:04x})",
        apikeyenvelope::DEFAULT_SUITE.aead_id()
    );
    println!("envelope     : {} bytes", envelope.len());
    println!("  {}", hex::encode(&envelope));

    section("3) Back inside the TD: open the envelope");
    let mut opened =
        apikeyenvelope::open(&enclave.secret_key, &envelope, SystemTime::now()).unwrap();
    println!("recovered    : {}", opened.api_key_str());
    println!(
        "key id       : {} (authenticated, not encrypted)",
        opened.metadata.key_id
    );
    println!("matches      : {}", opened.api_key == api_key);
    opened.wipe();

    section("4) What an attacker gets");
    // A different TD (or a replayed public key from another machine) cannot read it.
    let impostor = x25519::generate_keypair();
    println!(
        "wrong recipient key  : {}",
        failure_of(|| apikeyenvelope::open(&impostor.secret_key, &envelope, SystemTime::now()))
    );

    // The metadata is authenticated, so it cannot be relabelled in flight:
    // flip the last byte of the expiry timestamp, still inside the header.
    let mut relabelled = envelope.clone();
    let metadata_end = 20 + (((envelope[18] as usize) << 8) | envelope[19] as usize);
    relabelled[metadata_end - 1] ^= 0x01;
    println!(
        "relabelled expiry    : {}",
        failure_of(|| apikeyenvelope::open(&enclave.secret_key, &relabelled, SystemTime::now()))
    );

    // And so is the ciphertext.
    let mut tampered = envelope.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    println!(
        "flipped tag byte     : {}",
        failure_of(|| apikeyenvelope::open(&enclave.secret_key, &tampered, SystemTime::now()))
    );

    // An expired envelope is rejected even though it decrypts correctly.
    let expired_metadata = Metadata::with_expiry(
        "prod/ingest-api",
        Some(SystemTime::now() - Duration::from_secs(1)),
    )
    .unwrap();
    let stale = apikeyenvelope::seal(
        &enclave.public_key,
        &apikeyenvelope::random_api_key(),
        &expired_metadata,
    )
    .unwrap();
    println!(
        "expired envelope     : {}",
        failure_of(|| apikeyenvelope::open(&enclave.secret_key, &stale, SystemTime::now()))
    );

    section("5) The raw HPKE layer");
    let info = b"hearth-chain/example/v1";
    let sealed = hpke::seal(
        Suite::X25519Sha256ChaCha20Poly1305,
        &enclave.public_key,
        info,
        &[],
        b"any payload",
    )
    .unwrap();
    println!("enc (32 B)   : {}", hex::encode(&sealed.enc));
    println!("ciphertext   : {}", hex::encode(&sealed.ciphertext));
    let opened_raw = hpke::open(
        Suite::X25519Sha256ChaCha20Poly1305,
        &enclave.secret_key,
        &sealed.enc,
        info,
        &[],
        &sealed.ciphertext,
    )
    .unwrap();
    println!("opened       : {}", String::from_utf8_lossy(&opened_raw));
    println!();
}

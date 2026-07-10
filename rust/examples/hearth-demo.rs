//! Sample app for the hearth-chain crypto stack. Derives distinct signing / VRF
//! / BLS keys from one mnemonic, signs and verifies a message, then VRF-proves
//! an alpha and derives + verifies the VRF value beta.
//!
//! Usage: `cargo run --example hearth-demo -- [mnemonic] [messageBase64] [alphaBase64]`

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hearth::{address, bip39, ecvrf, ed25519, hex, keytree};

const DEFAULT_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ACCOUNT: u32 = 0;

fn section(title: &str) {
    println!("\n== {title} ==");
}

fn arg<'a>(args: &'a [String], i: usize, fallback: &'a str) -> &'a str {
    args.get(i)
        .filter(|s| !s.is_empty())
        .map(String::as_str)
        .unwrap_or(fallback)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mnemonic = arg(&args, 0, DEFAULT_MNEMONIC);
    let default_msg = STANDARD.encode("hearth-chain block header");
    let default_alpha = STANDARD.encode("epoch-42-slot-7");
    let message_b64 = arg(&args, 1, &default_msg);
    let alpha_b64 = arg(&args, 2, &default_alpha);

    section("0) Inputs");
    println!("crypto backend : pure-Rust (curve25519-dalek + ed25519-dalek)");
    println!("mnemonic       : {mnemonic}");
    if let Err(e) = bip39::validate(mnemonic) {
        println!("mnemonic check : INVALID ({e})");
        std::process::exit(1);
    }
    println!("mnemonic check : VALID (BIP-39 checksum ok)");

    // (1) Derive keys — one mnemonic, separate per-role / per-curve trees
    section("1) Key derivation (one mnemonic -> distinct signing / VRF / BLS keys)");
    let seed = bip39::to_seed(mnemonic, "");
    let signing = keytree::signing_key(&seed, ACCOUNT).unwrap();
    let vrf = keytree::vrf_key(&seed, ACCOUNT).unwrap();
    let bls_sk = keytree::bls_secret_key(&seed, ACCOUNT).unwrap();
    println!("BIP-39 seed    : {}", hex::encode(&seed));
    println!();
    println!("signing path   : {}", keytree::signing_path(ACCOUNT));
    println!("signing pubkey : {}", hex::encode(&signing.public_key));
    println!(
        "address (main) : {}",
        address::from_public_key(&signing.public_key, address::Network::Mainnet).unwrap()
    );
    println!(
        "address (test) : {}",
        address::from_public_key(&signing.public_key, address::Network::Testnet).unwrap()
    );
    println!();
    println!("VRF path       : {}", keytree::vrf_path(ACCOUNT));
    println!(
        "VRF pubkey     : {}  (distinct scalar from signing)",
        hex::encode(&vrf.public_key)
    );
    println!();
    println!(
        "BLS path       : {}  (EIP-2333, no hardened marker)",
        keytree::bls_path(ACCOUNT)
    );
    println!(
        "BLS secret key : {}  (32-byte scalar mod r)",
        hex::encode(&bls_sk)
    );

    // (2) Sign a base64 message with the signing key
    section("2) Ed25519 sign (RFC 8032, Ledger-native) - signing key");
    let message = STANDARD.decode(message_b64).unwrap();
    let signature = signing.sign(&message);
    println!("message (b64)  : {message_b64}");
    println!("message (hex)  : {}", hex::encode(&message));
    println!("signature      : {}  (64 bytes)", hex::encode(&signature));

    // (3) Verify the signature
    section("3) Ed25519 verify");
    println!(
        "verify         : {}",
        if ed25519::verify(&signature, &message, &signing.public_key) {
            "VALID"
        } else {
            "INVALID"
        }
    );
    let mut tampered = message.clone();
    if let Some(first) = tampered.first_mut() {
        *first ^= 0x01;
    }
    println!(
        "verify tampered: {}",
        if ed25519::verify(&signature, &tampered, &signing.public_key) {
            "VALID (!)"
        } else {
            "INVALID (expected)"
        }
    );

    // (4) VRF sign and derive VRF value with the VRF key
    section("4) ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381) - VRF key");
    let alpha = STANDARD.decode(alpha_b64).unwrap();
    let (proof, beta) = ecvrf::prove(&vrf.seed, &alpha);
    let vrf_ok = ecvrf::verify(&vrf.public_key, &alpha, &proof.bytes());
    println!("alpha (b64)    : {alpha_b64}");
    println!("alpha (hex)    : {}", hex::encode(&alpha));
    println!(
        "pi (proof)     : {}  (80 bytes)",
        hex::encode(&proof.bytes())
    );
    println!("  gamma        : {}", hex::encode(&proof.gamma));
    println!("  c            : {}", hex::encode(&proof.c));
    println!("  s            : {}", hex::encode(&proof.s));
    println!("beta (VRF out) : {}  (64 bytes)", hex::encode(&beta));
    println!(
        "vrf verify     : {}",
        if vrf_ok.is_some() { "VALID" } else { "INVALID" }
    );
    if let Some(b) = vrf_ok {
        println!(
            "vrf verify beta: {}  (matches: {})",
            hex::encode(&b),
            b == beta
        );
    }
}

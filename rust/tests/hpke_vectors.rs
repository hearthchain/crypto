//! RFC 9180 Appendix A base-mode test vectors for DHKEM(X25519, HKDF-SHA256)
//! + HKDF-SHA256, plus ApiKeyEnvelope round-trip/tamper/expiry coverage.

use std::time::{Duration, SystemTime};

use hearth::apikeyenvelope::{self, Metadata};
use hearth::hex;
use hearth::hpke::{self, Suite};
use hearth::x25519;

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn hx32(s: &str) -> [u8; 32] {
    hx(s).try_into().unwrap()
}

struct Vector {
    suite: Suite,
    info: &'static str,
    sk_em: &'static str,
    pk_em: &'static str,
    sk_rm: &'static str,
    pk_rm: &'static str,
    shared_secret: &'static str,
    key: &'static str,
    base_nonce: &'static str,
    exporter_secret: &'static str,
    pt: &'static str,
    aad: &'static str,
    ct: &'static str,
}

const A1: Vector = Vector {
    suite: Suite::X25519Sha256Aes128Gcm,
    info: "4f6465206f6e2061204772656369616e2055726e",
    sk_em: "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
    pk_em: "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
    sk_rm: "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
    pk_rm: "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
    shared_secret: "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
    key: "4531685d41d65f03dc48f6b8302c05b0",
    base_nonce: "56d890e5accaaf011cff4b7d",
    exporter_secret: "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8",
    pt: "4265617574792069732074727574682c20747275746820626561757479",
    aad: "436f756e742d30",
    ct: "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
};

const A2: Vector = Vector {
    suite: Suite::X25519Sha256ChaCha20Poly1305,
    info: "4f6465206f6e2061204772656369616e2055726e",
    sk_em: "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",
    pk_em: "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
    sk_rm: "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
    pk_rm: "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
    shared_secret: "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7",
    key: "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91",
    base_nonce: "5c4d98150661b848853b547f",
    exporter_secret: "a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922",
    pt: "4265617574792069732074727574682c20747275746820626561757479",
    aad: "436f756e742d30",
    ct: "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
};

fn check_vector(v: &Vector) {
    let sk_em = hx32(v.sk_em);
    let pk_em = hx32(v.pk_em);
    let sk_rm = hx32(v.sk_rm);
    let pk_rm = hx32(v.pk_rm);
    let info = hx(v.info);
    let aad = hx(v.aad);
    let pt = hx(v.pt);

    // The keypairs in the vector are self-consistent under our X25519.
    assert_eq!(x25519::public_key(&sk_em), pk_em, "pkEm");
    assert_eq!(x25519::public_key(&sk_rm), pk_rm, "pkRm");

    // DHKEM Encap and Decap agree on the shared secret, and match the vector.
    let enc = pk_em;
    let encapped = hpke::extract_and_expand(&x25519::dh(&sk_em, &pk_rm).unwrap(), &enc, &pk_rm);
    let decapped = hpke::extract_and_expand(&x25519::dh(&sk_rm, &enc).unwrap(), &enc, &pk_rm);
    assert_eq!(
        hex::encode(&encapped),
        v.shared_secret,
        "Encap shared_secret"
    );
    assert_eq!(
        hex::encode(&decapped),
        v.shared_secret,
        "Decap shared_secret"
    );

    // The key schedule.
    let shared_secret = hx32(v.shared_secret);
    let context = hpke::key_schedule(v.suite, &shared_secret, &info);
    assert_eq!(hex::encode(&context.key), v.key, "key");
    assert_eq!(hex::encode(&context.base_nonce), v.base_nonce, "base_nonce");
    assert_eq!(
        hex::encode(&context.exporter_secret),
        v.exporter_secret,
        "exporter_secret"
    );

    // Seal at sequence number 0.
    let sealed = hpke::seal_with_ephemeral(v.suite, &sk_em, &pk_rm, &info, &aad, &pt).unwrap();
    assert_eq!(sealed.enc, enc, "enc");
    assert_eq!(hex::encode(&sealed.ciphertext), v.ct, "ct");

    // And Open recovers the plaintext.
    let ct = hx(v.ct);
    let opened = hpke::open(v.suite, &sk_rm, &enc, &info, &aad, &ct).unwrap();
    assert_eq!(hex::encode(&opened), v.pt, "pt");
}

#[test]
fn rfc9180_appendix_a1_aes128gcm() {
    check_vector(&A1);
}

#[test]
fn rfc9180_appendix_a2_chacha20poly1305() {
    check_vector(&A2);
}

#[test]
fn seal_open_round_trip_every_suite() {
    for suite in [
        Suite::X25519Sha256Aes128Gcm,
        Suite::X25519Sha256Aes256Gcm,
        Suite::X25519Sha256ChaCha20Poly1305,
    ] {
        let recipient = x25519::generate_keypair();
        let info = b"hearth-test/info";
        let aad = b"hearth-test/aad";
        let plaintext = b"the quick brown fox";

        let sealed = hpke::seal(suite, &recipient.public_key, info, aad, plaintext).unwrap();
        assert_eq!(sealed.enc.len(), hpke::ENC_BYTES);
        assert_eq!(sealed.ciphertext.len(), plaintext.len() + hpke::TAG_BYTES);
        let opened = hpke::open(
            suite,
            &recipient.secret_key,
            &sealed.enc,
            info,
            aad,
            &sealed.ciphertext,
        )
        .unwrap();
        assert_eq!(opened, plaintext);
    }
}

#[test]
fn seal_is_randomized_per_call() {
    let recipient = x25519::generate_keypair();
    let first = hpke::seal(
        Suite::X25519Sha256ChaCha20Poly1305,
        &recipient.public_key,
        b"i",
        b"a",
        b"p",
    )
    .unwrap();
    let second = hpke::seal(
        Suite::X25519Sha256ChaCha20Poly1305,
        &recipient.public_key,
        b"i",
        b"a",
        b"p",
    )
    .unwrap();
    assert_ne!(first.enc, second.enc);
    assert_ne!(first.ciphertext, second.ciphertext);
}

#[test]
fn open_rejects_wrong_info_aad_key_or_ciphertext() {
    let recipient = x25519::generate_keypair();
    let info = b"info";
    let aad = b"aad";
    let suite = Suite::X25519Sha256ChaCha20Poly1305;
    let sealed = hpke::seal(suite, &recipient.public_key, info, aad, b"secret").unwrap();

    assert!(
        hpke::open(
            suite,
            &recipient.secret_key,
            &sealed.enc,
            b"other",
            aad,
            &sealed.ciphertext
        )
        .is_err()
    );
    assert!(
        hpke::open(
            suite,
            &recipient.secret_key,
            &sealed.enc,
            info,
            b"other",
            &sealed.ciphertext
        )
        .is_err()
    );
    let other = x25519::generate_keypair();
    assert!(
        hpke::open(
            suite,
            &other.secret_key,
            &sealed.enc,
            info,
            aad,
            &sealed.ciphertext
        )
        .is_err()
    );

    let mut tampered = sealed.ciphertext.clone();
    tampered[0] ^= 0x01;
    assert!(
        hpke::open(
            suite,
            &recipient.secret_key,
            &sealed.enc,
            info,
            aad,
            &tampered
        )
        .is_err()
    );
}

#[test]
fn x25519_rejects_small_order_public_key() {
    // The all-zero u-coordinate is the canonical small-order point; RFC 9180
    // requires the KEM to abort rather than derive from an all-zero DH output.
    let small_order = [0u8; 32];
    let kp = x25519::generate_keypair();
    assert!(x25519::dh(&kp.secret_key, &small_order).is_err());
}

#[test]
fn x25519_rejects_other_degenerate_public_keys() {
    // Beyond the trivial all-zero point: every other canonical low-order/invalid
    // u-coordinate (u=1, and the boundary encodings p-1, p, p+1 for
    // p = 2^255-19), little-endian. Under X25519's mandatory scalar clamping
    // (which forces the scalar to be a multiple of 8) every point of order
    // dividing 8 collapses to the identity, so the DH output is all-zero for
    // every one of these too — confirmed against a raw (unclamped-check)
    // Montgomery ladder, independent of this crate. This is why the single
    // all-zero-output check above is a complete mitigation, not just a
    // heuristic for the one obvious case.
    let vectors = [
        ("u=1",   "0100000000000000000000000000000000000000000000000000000000000000"),
        ("u=p-1", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ("u=p",   "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ("u=p+1", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    ];
    let kp = x25519::generate_keypair();
    for (name, h) in vectors {
        assert!(
            x25519::dh(&kp.secret_key, &hx32(h)).is_err(),
            "{name}: expected error for degenerate public key"
        );
    }
}

#[test]
fn suite_lookup_by_aead_id() {
    for suite in [
        Suite::X25519Sha256Aes128Gcm,
        Suite::X25519Sha256Aes256Gcm,
        Suite::X25519Sha256ChaCha20Poly1305,
    ] {
        assert_eq!(Suite::from_aead_id(suite.aead_id()).unwrap(), suite);
    }
    assert!(Suite::from_aead_id(0x00ff).is_err());
}

// --- ApiKeyEnvelope --------------------------------------------------------

fn meta() -> Metadata {
    Metadata::with_expiry("prod/ingest-api", Some(later())).unwrap()
}

fn now() -> SystemTime {
    // A fixed instant, matching the Java suite's NOW = 2026-08-05T12:00:00Z.
    SystemTime::UNIX_EPOCH + Duration::from_secs(1785931200)
}

fn later() -> SystemTime {
    now() + Duration::from_secs(3600)
}

#[test]
fn envelope_seal_open_round_trip_every_suite() {
    for suite in [
        Suite::X25519Sha256Aes128Gcm,
        Suite::X25519Sha256Aes256Gcm,
        Suite::X25519Sha256ChaCha20Poly1305,
    ] {
        let recipient = x25519::generate_keypair();
        let api_key = apikeyenvelope::random_api_key();

        let envelope =
            apikeyenvelope::seal_with_suite(&recipient.public_key, &api_key, &meta(), suite)
                .unwrap();

        let metadata_length = 1 + "prod/ingest-api".len() + 8;
        assert_eq!(envelope.len(), 20 + metadata_length + 32 + 48);

        let opened = apikeyenvelope::open(&recipient.secret_key, &envelope, now()).unwrap();
        assert_eq!(opened.api_key, api_key);
        assert_eq!(opened.metadata.key_id, "prod/ingest-api");
        assert_eq!(opened.metadata.not_after, Some(later()));
    }
}

#[test]
fn opened_wipe_zeroes_the_key() {
    let recipient = x25519::generate_keypair();
    let envelope = apikeyenvelope::seal(
        &recipient.public_key,
        &apikeyenvelope::random_api_key(),
        &meta(),
    )
    .unwrap();
    let mut opened = apikeyenvelope::open(&recipient.secret_key, &envelope, now()).unwrap();
    opened.wipe();
    assert_eq!(opened.api_key, vec![0u8; apikeyenvelope::API_KEY_LENGTH]);
}

#[test]
fn header_carries_the_suite_and_recipient_fingerprint() {
    let recipient = x25519::generate_keypair();
    let envelope = apikeyenvelope::seal(
        &recipient.public_key,
        &apikeyenvelope::random_api_key(),
        &meta(),
    )
    .unwrap();

    assert_eq!(&envelope[0..4], b"HKE1");
    assert_eq!(u16::from_be_bytes([envelope[4], envelope[5]]), hpke::KEM_ID);
    assert_eq!(u16::from_be_bytes([envelope[6], envelope[7]]), hpke::KDF_ID);
    assert_eq!(
        u16::from_be_bytes([envelope[8], envelope[9]]),
        apikeyenvelope::DEFAULT_SUITE.aead_id()
    );
    assert_eq!(
        &envelope[10..18],
        apikeyenvelope::fingerprint(&recipient.public_key)
    );
}

#[test]
fn rejects_envelope_for_another_recipient() {
    let recipient = x25519::generate_keypair();
    let other = x25519::generate_keypair();
    let envelope = apikeyenvelope::seal(
        &recipient.public_key,
        &apikeyenvelope::random_api_key(),
        &meta(),
    )
    .unwrap();

    let err = apikeyenvelope::open(&other.secret_key, &envelope, now()).unwrap_err();
    assert!(err.to_string().contains("different recipient key"), "{err}");
}

#[test]
fn rejects_expired_envelope() {
    let recipient = x25519::generate_keypair();
    let metadata =
        Metadata::with_expiry("short-lived", Some(now() - Duration::from_secs(1))).unwrap();
    let envelope = apikeyenvelope::seal(
        &recipient.public_key,
        &apikeyenvelope::random_api_key(),
        &metadata,
    )
    .unwrap();

    let err = apikeyenvelope::open(&recipient.secret_key, &envelope, now()).unwrap_err();
    assert!(err.to_string().starts_with("envelope expired"), "{err}");
}

#[test]
fn metadata_without_expiry_never_expires() {
    let recipient = x25519::generate_keypair();
    let metadata = Metadata::new("forever").unwrap();
    let envelope = apikeyenvelope::seal(
        &recipient.public_key,
        &apikeyenvelope::random_api_key(),
        &metadata,
    )
    .unwrap();

    let far_future = SystemTime::UNIX_EPOCH + Duration::from_secs(4_070_908_800); // 2099-01-01
    let opened = apikeyenvelope::open(&recipient.secret_key, &envelope, far_future).unwrap();
    assert_eq!(opened.metadata.not_after, None);
}

#[test]
fn rejects_tampered_metadata() {
    let recipient = x25519::generate_keypair();
    let metadata = Metadata::with_expiry("prod/ingest-api", Some(later())).unwrap();
    let envelope = apikeyenvelope::seal(
        &recipient.public_key,
        &apikeyenvelope::random_api_key(),
        &metadata,
    )
    .unwrap();

    let mut tampered = envelope.clone();
    let metadata_end = 20 + 1 + "prod/ingest-api".len() + 8;
    tampered[metadata_end - 1] ^= 0x01;

    let err = apikeyenvelope::open(&recipient.secret_key, &tampered, now()).unwrap_err();
    assert!(err.to_string().contains("not authentic"), "{err}");
}

#[test]
fn rejects_tampered_ciphertext_and_encapsulated_key() {
    let recipient = x25519::generate_keypair();
    let envelope = apikeyenvelope::seal(
        &recipient.public_key,
        &apikeyenvelope::random_api_key(),
        &meta(),
    )
    .unwrap();

    for offset in [envelope.len() - 1, envelope.len() - 40, envelope.len() - 60] {
        let mut tampered = envelope.clone();
        tampered[offset] ^= 0x01;
        assert!(
            apikeyenvelope::open(&recipient.secret_key, &tampered, now()).is_err(),
            "flipping byte {offset} should not open"
        );
    }
}

#[test]
fn rejects_malformed_envelopes() {
    let recipient = x25519::generate_keypair();
    let envelope = apikeyenvelope::seal(
        &recipient.public_key,
        &apikeyenvelope::random_api_key(),
        &meta(),
    )
    .unwrap();

    assert!(apikeyenvelope::open(&recipient.secret_key, &[0u8; 3], now()).is_err());

    let mut wrong_magic = envelope.clone();
    wrong_magic[0] = b'X';
    assert!(apikeyenvelope::open(&recipient.secret_key, &wrong_magic, now()).is_err());

    let truncated = &envelope[..envelope.len() - 1];
    assert!(apikeyenvelope::open(&recipient.secret_key, truncated, now()).is_err());

    let mut unknown_aead = envelope.clone();
    unknown_aead[9] = 0xff;
    assert!(apikeyenvelope::open(&recipient.secret_key, &unknown_aead, now()).is_err());
}

#[test]
fn rejects_api_keys_of_the_wrong_shape() {
    let public_key = x25519::generate_keypair().public_key;
    assert!(apikeyenvelope::seal(&public_key, b"tooshort", &meta()).is_err());
    assert!(
        apikeyenvelope::seal(&public_key, b"0123456789012345678901234567890!", &meta()).is_err()
    );
}

#[test]
fn metadata_rejects_empty_or_oversized_key_id() {
    assert!(Metadata::new("").is_err());
    assert!(Metadata::new("k".repeat(256)).is_err());
}

#[test]
fn random_api_key_is_alphanumeric_and_covers_the_alphabet() {
    let mut seen = std::collections::HashSet::new();
    for _ in 0..200 {
        let key = apikeyenvelope::random_api_key();
        assert_eq!(key.len(), apikeyenvelope::API_KEY_LENGTH);
        for &b in &key {
            assert!(b.is_ascii_alphanumeric(), "not ASCII alphanumeric: {b}");
            seen.insert(b);
        }
    }
    // 6400 draws over a 62-character alphabet: every character should appear.
    assert_eq!(seen.len(), 62);
}

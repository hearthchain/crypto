//! Official test vectors + cross-parity with the Java/Python/Go builds.

use hearth::{address, bech32m, bip39, bls, ecvrf, ed25519, hex, keytree};
use num_bigint::BigUint;

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

// --- BIP-39 --------------------------------------------------------------

#[test]
fn bip39_trezor_seed() {
    assert!(bip39::validate(ABANDON).is_ok());
    assert_eq!(
        hex::encode(&bip39::to_seed(ABANDON, "TREZOR")),
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
    );
}

#[test]
fn bip39_rejects_bad_checksum() {
    let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    assert!(bip39::validate(bad).is_err());
}

// --- SLIP-0010 -----------------------------------------------------------

#[test]
fn slip10_ed25519_vector1() {
    let seed = hx("000102030405060708090a0b0c0d0e0f");
    let m = hearth::slip10::master(&seed);
    assert_eq!(
        hex::encode(&m.chain_code),
        "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"
    );
    assert_eq!(
        hex::encode(&m.private_key),
        "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"
    );
    let m0 = hearth::slip10::derive_path(&seed, "m/0'").unwrap();
    assert_eq!(
        hex::encode(&m0.chain_code),
        "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69"
    );
    assert_eq!(
        hex::encode(&m0.private_key),
        "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"
    );
}

// --- RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI ------------------------------

#[test]
fn rfc9381() {
    let vectors: &[(&str, &str, &str, &str, &str)] = &[
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805",
            "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02",
            "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e",
            "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f",
        ),
    ];
    for (sk, pk, alpha, pi, beta) in vectors {
        let seed = hx(sk);
        let alpha = hx(alpha);
        assert_eq!(
            hex::encode(&ed25519::KeyPair::from_seed(&seed).unwrap().public_key),
            *pk
        );
        let (proof, beta_out) = ecvrf::prove(&seed, &alpha);
        assert_eq!(hex::encode(&proof.bytes()), *pi, "pi");
        assert_eq!(hex::encode(&beta_out), *beta, "beta");
        let verified = ecvrf::verify(&hx(pk), &alpha, &hx(pi)).expect("valid proof");
        assert_eq!(hex::encode(&verified), *beta);
        let mut wrong_alpha = alpha.clone();
        wrong_alpha.push(0);
        assert!(ecvrf::verify(&hx(pk), &wrong_alpha, &hx(pi)).is_none());
    }
}

#[test]
fn ed25519_sign_verify() {
    let kp = ed25519::KeyPair::from_seed(&hx(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ))
    .unwrap();
    let sig = kp.sign(b"hello hearth");
    assert!(ed25519::verify(&sig, b"hello hearth", &kp.public_key));
    assert!(!ed25519::verify(&sig, b"hello hearthh", &kp.public_key));
}

// --- EIP-2333 ------------------------------------------------------------

#[test]
fn eip2333() {
    let vectors: &[(&str, &str, u32, &str)] = &[
        (
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
            "6083874454709270928345386274498605044986640685124978867557563392430687146096",
            0,
            "20397789859736650942317412262472558107875392172444076792671091975210932703118",
        ),
        (
            "3141592653589793238462643383279502884197169399375105820974944592",
            "29757020647961307431480504535336562678282505419141012933316116377660817309383",
            3141592653,
            "25457201688850691947727629385191704516744796114925897962676248250929345014287",
        ),
        (
            "0099ff991111002299dd7744ee3355bbdd8844115566cc55663355668888cc00",
            "27580842291869792442942448775674722299803720648445448686099262467207037398656",
            4294967295,
            "29358610794459428860402234341874281240803786294062035874021252734817515685787",
        ),
        (
            "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
            "19022158461524446591288038168518313374041767046816487870552872741050760015818",
            42,
            "31372231650479070279774297061823572166496564838472787488249775572789064611981",
        ),
    ];
    for (seed, master, index, child) in vectors {
        let master_sk = bls::derive_master_sk(&hx(seed)).unwrap();
        assert_eq!(master_sk.len(), 32);
        assert_eq!(BigUint::from_bytes_be(&master_sk).to_string(), *master);
        let child_sk = bls::derive_child_sk(&master_sk, *index);
        assert_eq!(BigUint::from_bytes_be(&child_sk).to_string(), *child);
    }
}

#[test]
fn eip2334_hardened_rejection() {
    let seed = hx("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3");
    let via_path = bls::derive_path(&seed, "m/42").unwrap();
    let via_steps = bls::derive_child_sk(&bls::derive_master_sk(&seed).unwrap(), 42);
    assert_eq!(via_path, via_steps);
    assert_eq!(
        bls::derive_path(&seed, "m/12381/9381/0/0").unwrap().len(),
        32
    );
    assert!(bls::parse_path("m/12381/9381/0'/0").is_err());
}

// --- Bech32m / Address ---------------------------------------------------

#[test]
fn bech32m_vectors() {
    let valid = [
        "A1LQFN3A",
        "a1lqfn3a",
        "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
        "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
        "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
        "?1v759aa",
    ];
    for s in valid {
        assert!(bech32m::decode_raw(s).is_some(), "should decode: {s}");
    }
    for s in ["a1lqfn3q", "A1lqfn3a", "1lqfn3a"] {
        assert!(bech32m::decode_raw(s).is_none(), "should reject: {s}");
    }
}

#[test]
fn address_pinned() {
    let pk = hx("058b96bd967c4ad867eaab255dbce080cb1a45d03cf622caf8c16e4d871b0196");
    let a = address::Address::from_public_key(&pk).unwrap();

    // One identity, rendered per network via the HRP. These are the same strings
    // the Java suite pins.
    assert_eq!(
        a.to_bech32(address::MAINNET_HRP),
        "hrth19uvmpe6ll76dav0mvk06d35att3wk7a7gm8xwm"
    );
    assert_eq!(
        a.to_bech32(address::TESTNET_HRP),
        "thrth19uvmpe6ll76dav0mvk06d35att3wk7a7vvkkh7"
    );

    // Parse requires the HRP to match the requested one.
    let main = a.to_bech32(address::MAINNET_HRP);
    assert_eq!(
        address::Address::parse(&main, address::MAINNET_HRP),
        Some(a)
    );
    assert_eq!(address::Address::parse(&main, address::TESTNET_HRP), None);
    assert_eq!(
        address::Address::hrp_of(&main).as_deref(),
        Some(address::MAINNET_HRP)
    );

    // The 20-byte on-chain form round-trips, and the network is not in it.
    let payload = a.to_bytes();
    assert_eq!(payload.len(), address::HASH_LEN);
    assert_eq!(address::Address::from_bytes(&payload), Some(a));
    assert_eq!(address::Address::from_bytes(&[0u8; 19]), None);
    assert_ne!(
        a.to_bech32(address::MAINNET_HRP),
        a.to_bech32(address::TESTNET_HRP)
    );
}

// --- Seedless signing keys -----------------------------------------------

const RFC8032_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

/// A seed key exported to expanded form and re-imported is the same key — same
/// public key, same address, and byte-identical signatures, even though the two
/// sign by different internal paths (ed25519-dalek's signer vs. the RFC 8032
/// steps over the scalar). EdDSA is deterministic, so "same key" here means
/// literally the same bytes out.
#[test]
fn expanded_key_round_trips_from_seed() {
    let seed_key = ed25519::KeyPair::from_seed(&hx(RFC8032_SEED)).unwrap();
    let expanded = seed_key.to_expanded_key();
    let imported = ed25519::KeyPair::from_expanded_key(&expanded).unwrap();

    assert_eq!(seed_key.public_key, imported.public_key);
    assert_eq!(seed_key.to_address(), imported.to_address());
    assert_eq!(expanded, imported.to_expanded_key());
    assert!(seed_key.seed().is_some());
    assert!(imported.seed().is_none());

    let msg = b"hello hearth";
    assert_eq!(seed_key.sign(msg), imported.sign(msg));
    assert!(ed25519::verify(
        &imported.sign(msg),
        msg,
        &imported.public_key
    ));

    // The exported scalar is RFC 8032's clamped one: bit 254 set, low 3 bits
    // clear — so it is above L, i.e. import must accept non-reduced scalars or a
    // seed key could not round-trip at all.
    assert_eq!(expanded[31] & 0x40, 0x40);
    assert_eq!(expanded[0] & 0x07, 0);
}

/// The vanity-search premise: a generator walks candidates by repeated point
/// addition, `A_i = A_{i-1} + B` (i.e. `a_i = a_{i-1} + 1`), producing a scalar
/// with no seed behind it and no clamping bits. Such a key must import, sign and
/// verify like any other.
#[test]
fn key_from_incremented_scalar() {
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;

    let previous = ed25519::KeyPair::from_seed(&hx(RFC8032_SEED)).unwrap();
    let mut base = [0u8; 32];
    base.copy_from_slice(&previous.to_expanded_key()[..32]);
    let next = Scalar::from_bytes_mod_order(base) + Scalar::ONE;

    let key = ed25519::KeyPair::from_scalar(&next.to_bytes()).unwrap();

    // Reduced mod L the scalar no longer satisfies clamping; import must not care.
    assert_ne!(next.to_bytes()[31] & 0x40, 0x40);

    // The public key is exactly the point addition the generator performs, so the
    // generator can match candidate addresses without ever building a key.
    let stepped = CompressedEdwardsY(previous.public_key)
        .decompress()
        .unwrap()
        + ED25519_BASEPOINT_POINT;
    assert_eq!(stepped.compress().to_bytes(), key.public_key);

    let msg = b"signed by a ground key";
    assert!(ed25519::verify(&key.sign(msg), msg, &key.public_key));
    assert!(!ed25519::verify(&key.sign(msg), msg, &previous.public_key));
}

/// Pinned seedless-key vectors — the same values the Java suite pins.
#[test]
fn seedless_keys_pinned() {
    let expanded = hx(concat!(
        "836b2194dc19add1d9433a016dcf9004236ca1dba85d93e1394679e51cd5d70f",
        "fceac21612dc9d313d814e61fb2b29b5a62b70ec304ddb35065e8d801a01f4c6"
    ));
    let key = ed25519::KeyPair::from_expanded_key(&expanded).unwrap();

    assert_eq!(
        hex::encode(&key.public_key),
        "4fbb4b65d86e26261b9c36fb892274239506c6fcc3baa6d145979beaf3622eb5"
    );
    assert_eq!(
        key.to_address().to_bech32(address::MAINNET_HRP),
        "hrth18x0mux45uy7d4lhvcna7net8zcmurgrcvaz0x8"
    );
    assert_eq!(
        key.to_address().to_bech32(address::TESTNET_HRP),
        "thrth18x0mux45uy7d4lhvcna7net8zcmurgrcg2nllz"
    );
    assert_eq!(
        hex::encode(&key.sign(b"hello hearth")),
        concat!(
            "99991ffd3839e4281ea7c141f1b3914aa7640e7ecaf84c70f78866944eb75602",
            "54441f3595766cdb52358612acb805f7c712f72a0f836d815ed208eedacddd0c"
        )
    );

    // The same scalar imported bare: same public key, prefix derived from it.
    let from_scalar = ed25519::KeyPair::from_scalar(&expanded[..32]).unwrap();
    assert_eq!(from_scalar.public_key, key.public_key);
    assert_eq!(
        hex::encode(&from_scalar.to_expanded_key()),
        concat!(
            "836b2194dc19add1d9433a016dcf9004236ca1dba85d93e1394679e51cd5d70f",
            "77e9580f2a6acea97d2a19731a144407c24f1a86356844fe0fe8ed5ea8fa1bdd"
        )
    );
    // Deterministic: 32 bytes rebuild the identical key anywhere.
    assert_eq!(
        from_scalar.to_expanded_key(),
        ed25519::KeyPair::from_scalar(&expanded[..32])
            .unwrap()
            .to_expanded_key()
    );
}

#[test]
fn seedless_import_rejects_malformed_input() {
    assert!(ed25519::KeyPair::from_expanded_key(&[0u8; 63]).is_err());
    assert!(ed25519::KeyPair::from_expanded_key(&[0u8; 65]).is_err());
    assert!(ed25519::KeyPair::from_scalar(&[0u8; 31]).is_err());

    // A zero scalar gives the identity public key, which verify rejects for every
    // signature — the key would be unusable, so reject it here.
    assert!(ed25519::KeyPair::from_expanded_key(&[0u8; 64]).is_err());
    assert!(ed25519::KeyPair::from_scalar(&[0u8; 32]).is_err());

    // L itself, and any multiple of it, is also zero mod L.
    let order_l = hx("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    assert!(ed25519::KeyPair::from_scalar(&order_l).is_err());

    // Above the 255-bit range the group operations accept.
    let mut high_bit = [0u8; 32];
    high_bit[0] = 1;
    high_bit[31] = 0x80;
    assert!(ed25519::KeyPair::from_scalar(&high_bit).is_err());
}

// --- Cross-parity --------------------------------------------------------

#[test]
fn cross_parity() {
    let seed = bip39::to_seed(ABANDON, "");
    assert_eq!(
        hex::encode(&seed),
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
    );
    let signing = keytree::signing_key(&seed, 0).unwrap();
    let vrf = keytree::vrf_key(&seed, 0).unwrap();
    let bls_sk = keytree::bls_secret_key(&seed, 0).unwrap();
    assert_eq!(
        hex::encode(&signing.public_key),
        "058b96bd967c4ad867eaab255dbce080cb1a45d03cf622caf8c16e4d871b0196"
    );
    assert_eq!(
        hex::encode(&vrf.public_key),
        "06bc4b2bde1b328430ba118192c21980f4a9e7f424ad1fa31604a977c8d31657"
    );
    assert_eq!(
        hex::encode(&bls_sk),
        "28d0b232f19982772fd2fd9b22be335f2b76fd7a0d455a959a37465d38d089f1"
    );
    assert_ne!(
        hex::encode(&signing.public_key),
        hex::encode(&vrf.public_key)
    );
    assert_eq!(keytree::signing_path(0), "m/44'/9381'/0'/0'/0'");
    assert_eq!(keytree::vrf_path(0), "m/44'/9381'/0'/1'/0'");
}

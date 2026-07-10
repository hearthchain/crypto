//! Official test vectors + cross-parity with the Scala/Java/Python/Go builds.

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
    assert_eq!(
        address::from_public_key(&pk, address::Network::Mainnet).unwrap(),
        "hrthm1qqh3nv88tllmfh43ldjelfkxn4dw96mmhcj9u36h"
    );
    assert_eq!(
        address::from_public_key(&pk, address::Network::Testnet).unwrap(),
        "hrtht1qqh3nv88tllmfh43ldjelfkxn4dw96mmhcwumd6m"
    );
    let main = address::from_public_key(&pk, address::Network::Mainnet).unwrap();
    let parsed = address::parse(&main).unwrap();
    assert_eq!(parsed.network, address::Network::Mainnet);
    assert_eq!(parsed.hash.len(), 20);
    assert!(address::parse_for(&main, address::Network::Testnet).is_none());
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

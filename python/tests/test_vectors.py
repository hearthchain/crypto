"""Official crypto test vectors + cross-parity with the Scala implementation."""

from __future__ import annotations

import pytest

from hearth import address, bech32m, bip39, bls, ecvrf, ed25519, keytree, slip10
from hearth.address import Network

ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


# --- BIP-39 --------------------------------------------------------------


def test_bip39_trezor_seed() -> None:
    assert bip39.validate(ABANDON) is None
    seed = bip39.to_seed(ABANDON, "TREZOR")
    assert seed.hex() == (
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
        "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
    )


def test_bip39_rejects_bad_checksum() -> None:
    bad = "abandon " * 11 + "abandon"
    assert bip39.validate(bad) is not None


# --- SLIP-0010 -----------------------------------------------------------


def test_slip10_ed25519_vector1() -> None:
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    m = slip10.master(seed)
    assert m.chain_code.hex() == "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"
    assert m.private_key.hex() == "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"
    m0 = slip10.derive_path(seed, "m/0'")
    assert m0.chain_code.hex() == "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69"
    assert m0.private_key.hex() == "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"


# --- RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI ------------------------------

RFC9381 = [
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
]


@pytest.mark.parametrize(("sk", "pk", "alpha", "pi", "beta"), RFC9381)
def test_rfc9381(sk: str, pk: str, alpha: str, pi: str, beta: str) -> None:
    seed = bytes.fromhex(sk)
    alpha_b = bytes.fromhex(alpha)
    assert ed25519.from_seed(seed).public_key.hex() == pk
    proof, beta_out = ecvrf.prove(seed, alpha_b)
    assert proof.bytes.hex() == pi
    assert beta_out.hex() == beta
    verified = ecvrf.verify(bytes.fromhex(pk), alpha_b, bytes.fromhex(pi))
    assert verified is not None and verified.hex() == beta
    assert ecvrf.verify(bytes.fromhex(pk), alpha_b + b"\x00", bytes.fromhex(pi)) is None


def test_ed25519_sign_verify_roundtrip() -> None:
    kp = ed25519.from_seed(bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
    sig = kp.sign(b"hello hearth")
    assert ed25519.verify(sig, b"hello hearth", kp.public_key)
    assert not ed25519.verify(sig, b"hello hearthh", kp.public_key)


# --- EIP-2333 (BLS12-381 key derivation) ---------------------------------

EIP2333 = [
    (
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        6083874454709270928345386274498605044986640685124978867557563392430687146096,
        0,
        20397789859736650942317412262472558107875392172444076792671091975210932703118,
    ),
    (
        "3141592653589793238462643383279502884197169399375105820974944592",
        29757020647961307431480504535336562678282505419141012933316116377660817309383,
        3141592653,
        25457201688850691947727629385191704516744796114925897962676248250929345014287,
    ),
    (
        "0099ff991111002299dd7744ee3355bbdd8844115566cc55663355668888cc00",
        27580842291869792442942448775674722299803720648445448686099262467207037398656,
        4294967295,
        29358610794459428860402234341874281240803786294062035874021252734817515685787,
    ),
    (
        "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
        19022158461524446591288038168518313374041767046816487870552872741050760015818,
        42,
        31372231650479070279774297061823572166496564838472787488249775572789064611981,
    ),
]


@pytest.mark.parametrize(("seed", "master", "index", "child"), EIP2333)
def test_eip2333(seed: str, master: int, index: int, child: int) -> None:
    seed_b = bytes.fromhex(seed)
    master_sk = bls.derive_master_sk(seed_b)
    assert len(master_sk) == 32
    assert int.from_bytes(master_sk, "big") == master
    child_sk = bls.derive_child_sk(master_sk, index)
    assert int.from_bytes(child_sk, "big") == child


def test_eip2334_path_and_hardened_rejection() -> None:
    seed = bytes.fromhex("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
    assert bls.derive_path(seed, "m/42") == bls.derive_child_sk(bls.derive_master_sk(seed), 42)
    assert len(bls.derive_path(seed, "m/12381/9381/0/0")) == 32
    with pytest.raises(ValueError, match="hardened"):
        bls.parse_path("m/12381/9381/0'/0")


# --- Bech32m / Address ---------------------------------------------------

BECH32M_VALID = [
    "A1LQFN3A",
    "a1lqfn3a",
    "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
    "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
    "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
    "?1v759aa",
]


@pytest.mark.parametrize("s", BECH32M_VALID)
def test_bech32m_valid(s: str) -> None:
    assert bech32m.decode_raw(s) is not None


def test_bech32m_rejects() -> None:
    assert bech32m.decode_raw("a1lqfn3q") is None  # bad checksum
    assert bech32m.decode_raw("A1lqfn3a") is None  # mixed case
    assert bech32m.decode_raw("1lqfn3a") is None  # empty hrp


DEMO_PK = bytes.fromhex("058b96bd967c4ad867eaab255dbce080cb1a45d03cf622caf8c16e4d871b0196")


def test_address_pinned() -> None:
    assert address.from_public_key(DEMO_PK, Network.MAINNET) == "hrthm1qqh3nv88tllmfh43ldjelfkxn4dw96mmhcj9u36h"
    assert address.from_public_key(DEMO_PK, Network.TESTNET) == "hrtht1qqh3nv88tllmfh43ldjelfkxn4dw96mmhcwumd6m"


def test_address_parse_and_cross_network() -> None:
    s = address.from_public_key(DEMO_PK, Network.MAINNET)
    parsed = address.parse(s)
    assert parsed is not None and parsed.network == Network.MAINNET and len(parsed.hash) == 20
    assert address.parse_for(s, Network.TESTNET) is None
    tampered = s[:-1] + ("p" if s[-1] == "q" else "q")
    assert address.parse(tampered) is None


# --- Cross-parity with the Scala build (same mnemonic -> same bytes) ------


def test_cross_parity_with_scala() -> None:
    seed = bip39.to_seed(ABANDON)
    assert seed.hex() == (
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
        "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
    )
    signing = keytree.signing_key(seed)
    vrf = keytree.vrf_key(seed)
    bls_sk = keytree.bls_secret_key(seed)
    assert signing.public_key.hex() == "058b96bd967c4ad867eaab255dbce080cb1a45d03cf622caf8c16e4d871b0196"
    assert vrf.public_key.hex() == "06bc4b2bde1b328430ba118192c21980f4a9e7f424ad1fa31604a977c8d31657"
    assert bls_sk.hex() == "28d0b232f19982772fd2fd9b22be335f2b76fd7a0d455a959a37465d38d089f1"
    # signing and VRF keys are genuinely distinct
    assert signing.public_key != vrf.public_key
    assert keytree.signing_path() == "m/44'/9381'/0'/0'/0'"
    assert keytree.vrf_path() == "m/44'/9381'/0'/1'/0'"


def test_wordlist_matches_official_bip39() -> None:
    """Guard against drift: the embedded wordlist must be the official BIP-39 file."""
    import hashlib
    from importlib.resources import files

    data = files("hearth.data").joinpath("english.txt").read_bytes()
    assert (
        hashlib.sha256(data).hexdigest()
        == "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
    )

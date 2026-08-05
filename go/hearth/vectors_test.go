package hearth_test

import (
	"encoding/hex"
	"math/big"
	"testing"

	"hearthchain/hearth"
)

const abandon = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func eq(t *testing.T, got []byte, want, label string) {
	t.Helper()
	if hex.EncodeToString(got) != want {
		t.Errorf("%s\n got:  %s\n want: %s", label, hex.EncodeToString(got), want)
	}
}

// --- BIP-39 --------------------------------------------------------------

func TestBip39TrezorSeed(t *testing.T) {
	if err := hearth.ValidateMnemonic(abandon); err != nil {
		t.Fatalf("validate: %v", err)
	}
	seed := hearth.MnemonicToSeed(abandon, "TREZOR")
	eq(t, seed, "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04", "seed")
}

func TestBip39RejectsBadChecksum(t *testing.T) {
	bad := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
	if hearth.ValidateMnemonic(bad) == nil {
		t.Error("expected checksum error")
	}
}

// --- SLIP-0010 -----------------------------------------------------------

func TestSlip10Ed25519Vector1(t *testing.T) {
	seed := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	m := hearth.Slip10Master(seed)
	eq(t, m.ChainCode, "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb", "master chain code")
	eq(t, m.PrivateKey, "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7", "master priv")
	m0, err := hearth.Slip10DerivePath(seed, "m/0'")
	if err != nil {
		t.Fatal(err)
	}
	eq(t, m0.ChainCode, "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69", "m/0' chain code")
	eq(t, m0.PrivateKey, "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3", "m/0' priv")
}

// --- RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI ------------------------------

func TestRFC9381(t *testing.T) {
	vectors := []struct{ sk, pk, alpha, pi, beta string }{
		{
			"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
			"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
			"",
			"8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805",
			"90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae",
		},
		{
			"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
			"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
			"72",
			"f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02",
			"eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031",
		},
		{
			"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
			"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
			"af82",
			"9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e",
			"645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f",
		},
	}
	for i, v := range vectors {
		seed := mustHex(t, v.sk)
		alpha := mustHex(t, v.alpha)
		kp, err := hearth.KeyPairFromSeed(seed)
		if err != nil {
			t.Fatal(err)
		}
		eq(t, kp.PublicKey, v.pk, "pubkey")
		proof, beta, err := hearth.VRFProve(seed, alpha)
		if err != nil {
			t.Fatalf("vector %d prove: %v", i, err)
		}
		eq(t, proof.Bytes(), v.pi, "pi")
		eq(t, beta, v.beta, "beta")
		betaOut, ok := hearth.VRFVerify(mustHex(t, v.pk), alpha, mustHex(t, v.pi))
		if !ok {
			t.Fatalf("vector %d verify rejected a valid proof", i)
		}
		eq(t, betaOut, v.beta, "verify beta")
		if _, ok := hearth.VRFVerify(mustHex(t, v.pk), append(alpha, 0x00), mustHex(t, v.pi)); ok {
			t.Errorf("vector %d verify accepted wrong alpha", i)
		}
	}
}

func TestEd25519SignVerify(t *testing.T) {
	kp, _ := hearth.KeyPairFromSeed(mustHex(t, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
	sig := kp.Sign([]byte("hello hearth"))
	if !hearth.Verify(sig, []byte("hello hearth"), kp.PublicKey) {
		t.Error("valid signature rejected")
	}
	if hearth.Verify(sig, []byte("hello hearthh"), kp.PublicKey) {
		t.Error("tampered message accepted")
	}
}

// A small-order public key (in the limit, the identity: 0x01 followed by 31
// zero bytes) with R = the same point and S = 0 satisfies the raw
// verification equation [S]B = R + [k]A for every k, i.e. for every message —
// a universal forgery unless Verify rejects a small-order A or R. Go's
// stdlib crypto/ed25519.Verify does not do this on its own.
func TestEd25519RejectsSmallOrderPublicKeyForgery(t *testing.T) {
	identity := make([]byte, 32)
	identity[0] = 1
	forgedSig := make([]byte, 64) // R = identity, S = 0
	copy(forgedSig[:32], identity)

	if hearth.Verify(forgedSig, []byte("attacker forged message 1"), identity) {
		t.Error("forged signature accepted for message 1")
	}
	if hearth.Verify(forgedSig, []byte("totally different message 2"), identity) {
		t.Error("forged signature accepted for message 2")
	}
}

// --- EIP-2333 (BLS12-381 key derivation) ---------------------------------

func TestEIP2333(t *testing.T) {
	vectors := []struct {
		seed, master string
		index        uint32
		child        string
	}{
		{"c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04", "6083874454709270928345386274498605044986640685124978867557563392430687146096", 0, "20397789859736650942317412262472558107875392172444076792671091975210932703118"},
		{"3141592653589793238462643383279502884197169399375105820974944592", "29757020647961307431480504535336562678282505419141012933316116377660817309383", 3141592653, "25457201688850691947727629385191704516744796114925897962676248250929345014287"},
		{"0099ff991111002299dd7744ee3355bbdd8844115566cc55663355668888cc00", "27580842291869792442942448775674722299803720648445448686099262467207037398656", 4294967295, "29358610794459428860402234341874281240803786294062035874021252734817515685787"},
		{"d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3", "19022158461524446591288038168518313374041767046816487870552872741050760015818", 42, "31372231650479070279774297061823572166496564838472787488249775572789064611981"},
	}
	for i, v := range vectors {
		master, err := hearth.BLSDeriveMasterSK(mustHex(t, v.seed))
		if err != nil {
			t.Fatal(err)
		}
		if len(master) != 32 {
			t.Fatalf("vector %d: master not 32 bytes", i)
		}
		if got := new(big.Int).SetBytes(master).String(); got != v.master {
			t.Errorf("vector %d master:\n got:  %s\n want: %s", i, got, v.master)
		}
		child := hearth.BLSDeriveChildSK(master, v.index)
		if got := new(big.Int).SetBytes(child).String(); got != v.child {
			t.Errorf("vector %d child:\n got:  %s\n want: %s", i, got, v.child)
		}
	}
}

func TestEIP2334PathAndHardenedRejection(t *testing.T) {
	seed := mustHex(t, "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
	viaPath, err := hearth.BLSDerivePath(seed, "m/42")
	if err != nil {
		t.Fatal(err)
	}
	master, _ := hearth.BLSDeriveMasterSK(seed)
	if hex.EncodeToString(viaPath) != hex.EncodeToString(hearth.BLSDeriveChildSK(master, 42)) {
		t.Error("m/42 != deriveChild(master, 42)")
	}
	full, err := hearth.BLSDerivePath(seed, "m/12381/9381/0/0")
	if err != nil || len(full) != 32 {
		t.Fatalf("full path derive failed: %v", err)
	}
	if _, err := hearth.BLSParsePath("m/12381/9381/0'/0"); err == nil {
		t.Error("expected error on hardened BLS path")
	}
}

// --- Bech32m / Address ---------------------------------------------------

func TestBech32mValid(t *testing.T) {
	valid := []string{
		"A1LQFN3A",
		"a1lqfn3a",
		"an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
		"abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
		"split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
		"?1v759aa",
	}
	for _, s := range valid {
		if _, _, ok := hearth.Bech32mDecodeRaw(s); !ok {
			t.Errorf("should decode: %s", s)
		}
	}
	for _, s := range []string{"a1lqfn3q", "A1lqfn3a", "1lqfn3a"} {
		if _, _, ok := hearth.Bech32mDecodeRaw(s); ok {
			t.Errorf("should reject: %s", s)
		}
	}
}

var demoPK = "058b96bd967c4ad867eaab255dbce080cb1a45d03cf622caf8c16e4d871b0196"

func TestAddressPinned(t *testing.T) {
	pk := mustHex(t, demoPK)
	main, _ := hearth.AddressFromPublicKey(pk, hearth.Mainnet)
	test, _ := hearth.AddressFromPublicKey(pk, hearth.Testnet)
	if main != "hrthm1qqh3nv88tllmfh43ldjelfkxn4dw96mmhcj9u36h" {
		t.Errorf("mainnet address: %s", main)
	}
	if test != "hrtht1qqh3nv88tllmfh43ldjelfkxn4dw96mmhcwumd6m" {
		t.Errorf("testnet address: %s", test)
	}
	parsed, ok := hearth.ParseAddress(main)
	if !ok || parsed.Network != hearth.Mainnet || len(parsed.Hash) != 20 {
		t.Error("parse failed")
	}
	if _, ok := hearth.ParseAddressFor(main, hearth.Testnet); ok {
		t.Error("cross-network parse should fail")
	}
}

// --- Cross-parity with the other builds -----------------------------------

func TestCrossParity(t *testing.T) {
	seed := hearth.MnemonicToSeed(abandon, "")
	eq(t, seed, "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4", "seed")
	signing, _ := hearth.SigningKey(seed, 0)
	vrf, _ := hearth.VRFKey(seed, 0)
	blsSk, _ := hearth.BLSSecretKey(seed, 0)
	eq(t, signing.PublicKey, "058b96bd967c4ad867eaab255dbce080cb1a45d03cf622caf8c16e4d871b0196", "signing pubkey")
	eq(t, vrf.PublicKey, "06bc4b2bde1b328430ba118192c21980f4a9e7f424ad1fa31604a977c8d31657", "vrf pubkey")
	eq(t, blsSk, "28d0b232f19982772fd2fd9b22be335f2b76fd7a0d455a959a37465d38d089f1", "bls sk")
	if hex.EncodeToString(signing.PublicKey) == hex.EncodeToString(vrf.PublicKey) {
		t.Error("signing and VRF keys must differ")
	}
	if hearth.SigningPath(0) != "m/44'/9381'/0'/0'/0'" || hearth.VRFPath(0) != "m/44'/9381'/0'/1'/0'" {
		t.Error("unexpected derivation paths")
	}
}

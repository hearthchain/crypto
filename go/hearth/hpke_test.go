package hearth

// RFC 9180 Appendix A base-mode test vectors for DHKEM(X25519, HKDF-SHA256) +
// HKDF-SHA256.
//
// This file is package hearth (not hearth_test, unlike the rest of this
// package's tests) because the vectors pin the intermediate key-schedule and
// DHKEM outputs, which needs the unexported hpkeExtractAndExpand,
// hpkeKeySchedule and hpkeSealWithEphemeral — the same white-box access the
// Java port's package-private HpkeVectorsTest relies on.

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

type hpkeVector struct {
	name           string
	suite          HpkeSuite
	info           string
	skEm           string
	pkEm           string
	skRm           string
	pkRm           string
	sharedSecret   string
	key            string
	baseNonce      string
	exporterSecret string
	pt             string
	aad            string
	ct             string
}

// RFC 9180 A.1: AES-128-GCM.
var hpkeVectorA1 = hpkeVector{
	name:           "A.1",
	suite:          HpkeX25519Sha256Aes128Gcm,
	info:           "4f6465206f6e2061204772656369616e2055726e",
	skEm:           "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
	pkEm:           "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
	skRm:           "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
	pkRm:           "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
	sharedSecret:   "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
	key:            "4531685d41d65f03dc48f6b8302c05b0",
	baseNonce:      "56d890e5accaaf011cff4b7d",
	exporterSecret: "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8",
	pt:             "4265617574792069732074727574682c20747275746820626561757479",
	aad:            "436f756e742d30",
	ct:             "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
}

// RFC 9180 A.2: ChaCha20-Poly1305.
var hpkeVectorA2 = hpkeVector{
	name:           "A.2",
	suite:          HpkeX25519Sha256ChaCha20Poly1305,
	info:           "4f6465206f6e2061204772656369616e2055726e",
	skEm:           "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",
	pkEm:           "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
	skRm:           "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
	pkRm:           "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
	sharedSecret:   "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7",
	key:            "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91",
	baseNonce:      "5c4d98150661b848853b547f",
	exporterSecret: "a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922",
	pt:             "4265617574792069732074727574682c20747275746820626561757479",
	aad:            "436f756e742d30",
	ct:             "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
}

func checkHpkeVector(t *testing.T, v hpkeVector) {
	t.Helper()

	// The keypairs in the vector are self-consistent under our X25519.
	pkEm, err := X25519PublicKey(hx(t, v.skEm))
	if err != nil {
		t.Fatalf("%s: pkEm: %v", v.name, err)
	}
	if !bytes.Equal(pkEm, hx(t, v.pkEm)) {
		t.Errorf("%s: pkEm mismatch", v.name)
	}
	pkRm, err := X25519PublicKey(hx(t, v.skRm))
	if err != nil {
		t.Fatalf("%s: pkRm: %v", v.name, err)
	}
	if !bytes.Equal(pkRm, hx(t, v.pkRm)) {
		t.Errorf("%s: pkRm mismatch", v.name)
	}

	// DHKEM Encap and Decap agree on the shared secret, and match the vector.
	enc := hx(t, v.pkEm)
	dhEm, err := X25519DH(hx(t, v.skEm), hx(t, v.pkRm))
	if err != nil {
		t.Fatalf("%s: Encap DH: %v", v.name, err)
	}
	encapped := hpkeExtractAndExpand(dhEm, enc, hx(t, v.pkRm))
	dhRm, err := X25519DH(hx(t, v.skRm), enc)
	if err != nil {
		t.Fatalf("%s: Decap DH: %v", v.name, err)
	}
	decapped := hpkeExtractAndExpand(dhRm, enc, hx(t, v.pkRm))
	if !bytes.Equal(encapped, hx(t, v.sharedSecret)) {
		t.Errorf("%s: Encap shared_secret mismatch", v.name)
	}
	if !bytes.Equal(decapped, hx(t, v.sharedSecret)) {
		t.Errorf("%s: Decap shared_secret mismatch", v.name)
	}

	// The key schedule.
	ctx := hpkeKeySchedule(v.suite, hx(t, v.sharedSecret), hx(t, v.info))
	if !bytes.Equal(ctx.key, hx(t, v.key)) {
		t.Errorf("%s: key mismatch", v.name)
	}
	if !bytes.Equal(ctx.baseNonce, hx(t, v.baseNonce)) {
		t.Errorf("%s: base_nonce mismatch", v.name)
	}
	if !bytes.Equal(ctx.exporterSecret, hx(t, v.exporterSecret)) {
		t.Errorf("%s: exporter_secret mismatch", v.name)
	}

	// Seal at sequence number 0.
	sealed, err := hpkeSealWithEphemeral(v.suite, hx(t, v.skEm), hx(t, v.pkRm), hx(t, v.info), hx(t, v.aad), hx(t, v.pt))
	if err != nil {
		t.Fatalf("%s: seal: %v", v.name, err)
	}
	if !bytes.Equal(sealed.Enc, enc) {
		t.Errorf("%s: enc mismatch", v.name)
	}
	if !bytes.Equal(sealed.Ciphertext, hx(t, v.ct)) {
		t.Errorf("%s: ct mismatch", v.name)
	}

	// And Open recovers the plaintext.
	pt, err := HpkeOpen(v.suite, hx(t, v.skRm), enc, hx(t, v.info), hx(t, v.aad), hx(t, v.ct))
	if err != nil {
		t.Fatalf("%s: open: %v", v.name, err)
	}
	if !bytes.Equal(pt, hx(t, v.pt)) {
		t.Errorf("%s: pt mismatch", v.name)
	}
}

func TestHpkeRfc9180AppendixA1(t *testing.T) { checkHpkeVector(t, hpkeVectorA1) }
func TestHpkeRfc9180AppendixA2(t *testing.T) { checkHpkeVector(t, hpkeVectorA2) }

// AES-256-GCM has no X25519 vector in the RFC; cover it by round-trip.
func TestHpkeSealOpenRoundTrip(t *testing.T) {
	for _, suite := range hpkeSuites {
		t.Run(suite.String(), func(t *testing.T) {
			recipient, err := GenerateX25519KeyPair()
			if err != nil {
				t.Fatal(err)
			}
			info := []byte("hearth-test/info")
			aad := []byte("hearth-test/aad")
			plaintext := []byte("the quick brown fox")

			sealed, err := HpkeSeal(suite, recipient.PublicKey, info, aad, plaintext)
			if err != nil {
				t.Fatal(err)
			}
			if len(sealed.Enc) != HpkeEncBytes {
				t.Errorf("enc length = %d, want %d", len(sealed.Enc), HpkeEncBytes)
			}
			if len(sealed.Ciphertext) != len(plaintext)+HpkeTagBytes {
				t.Errorf("ciphertext length = %d, want %d", len(sealed.Ciphertext), len(plaintext)+HpkeTagBytes)
			}
			opened, err := HpkeOpen(suite, recipient.SecretKey, sealed.Enc, info, aad, sealed.Ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(opened, plaintext) {
				t.Errorf("opened = %q, want %q", opened, plaintext)
			}
		})
	}
}

func TestHpkeSealIsRandomizedPerCall(t *testing.T) {
	recipient, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	first, err := HpkeSeal(HpkeX25519Sha256ChaCha20Poly1305, recipient.PublicKey, []byte("i"), []byte("a"), []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := HpkeSeal(HpkeX25519Sha256ChaCha20Poly1305, recipient.PublicKey, []byte("i"), []byte("a"), []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Enc, second.Enc) {
		t.Error("expected enc to differ between calls")
	}
	if bytes.Equal(first.Ciphertext, second.Ciphertext) {
		t.Error("expected ciphertext to differ between calls")
	}
}

func TestHpkeOpenRejectsWrongInfoAadKeyOrCiphertext(t *testing.T) {
	recipient, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	info := []byte("info")
	aad := []byte("aad")
	suite := HpkeX25519Sha256ChaCha20Poly1305
	sealed, err := HpkeSeal(suite, recipient.PublicKey, info, aad, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := HpkeOpen(suite, recipient.SecretKey, sealed.Enc, []byte("other"), aad, sealed.Ciphertext); err == nil {
		t.Error("expected error for wrong info")
	}
	if _, err := HpkeOpen(suite, recipient.SecretKey, sealed.Enc, info, []byte("other"), sealed.Ciphertext); err == nil {
		t.Error("expected error for wrong aad")
	}
	other, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := HpkeOpen(suite, other.SecretKey, sealed.Enc, info, aad, sealed.Ciphertext); err == nil {
		t.Error("expected error for wrong key")
	}

	tampered := append([]byte(nil), sealed.Ciphertext...)
	tampered[0] ^= 0x01
	if _, err := HpkeOpen(suite, recipient.SecretKey, sealed.Enc, info, aad, tampered); err == nil {
		t.Error("expected error for tampered ciphertext")
	}
}

func TestX25519RejectsSmallOrderPublicKey(t *testing.T) {
	// The all-zero u-coordinate is the canonical small-order point; RFC 9180
	// requires the KEM to abort rather than derive from an all-zero DH output.
	recipient, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	smallOrder := make([]byte, X25519KeyBytes)
	if _, err := X25519DH(recipient.SecretKey, smallOrder); err == nil {
		t.Error("expected error for small-order public key")
	}
}

// Beyond the trivial all-zero point: every other canonical low-order/invalid
// u-coordinate (u=1, and the boundary encodings p-1, p, p+1 for
// p = 2^255-19), little-endian. Under X25519's mandatory scalar clamping
// (which forces the scalar to be a multiple of 8) every point of order
// dividing 8 collapses to the identity, so the DH output is all-zero for
// every one of these too — confirmed against a raw (unclamped-check)
// Montgomery ladder, independent of this library. This is why the single
// all-zero-output check above is a complete mitigation, not just a heuristic
// for the one obvious case.
func TestX25519RejectsOtherDegeneratePublicKeys(t *testing.T) {
	vectors := map[string]string{
		"u=1":   "0100000000000000000000000000000000000000000000000000000000000000",
		"u=p-1": "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"u=p":   "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"u=p+1": "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	}
	recipient, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	for name, h := range vectors {
		if _, err := X25519DH(recipient.SecretKey, hx(t, h)); err == nil {
			t.Errorf("%s: expected error for degenerate public key", name)
		}
	}
}

func TestHpkeSuiteLookupByAEADID(t *testing.T) {
	for _, suite := range hpkeSuites {
		got, err := HpkeSuiteFromAEADID(suite.AEADID())
		if err != nil || got != suite {
			t.Errorf("HpkeSuiteFromAEADID(%v) = %v, %v", suite.AEADID(), got, err)
		}
	}
	if _, err := HpkeSuiteFromAEADID(0x00ff); err == nil {
		t.Error("expected error for unknown AEAD id")
	}
}

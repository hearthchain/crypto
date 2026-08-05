package hearth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// HPKE (RFC 9180) single-shot public-key encryption, base mode, over
// DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256.
//
// Base mode means the sender is anonymous: anyone holding the recipient's
// public key can seal. That is exactly the shape of "encrypt a secret to a
// public key published by an enclave" — the recipient is authenticated (by
// attestation, out of band), the sender is authorized by the transport.
//
// Only the single-shot Seal/Open of RFC 9180 §6.1 is implemented — one
// message per encapsulation, always at sequence number 0. There is
// deliberately no stateful sender context to reuse, so a nonce can never be
// repeated under one key.
//
// The whole construction runs on the standard library plus
// golang.org/x/crypto/chacha20poly1305: HMAC-SHA256 via crypto/hmac, AES-GCM
// via crypto/cipher, ChaCha20-Poly1305 via x/crypto, and the group operation
// via X25519 (x25519.go). Verified against the RFC 9180 A.1 and A.2 test
// vectors.
//
// See ApiKeyEnvelope (apikeyenvelope.go) for the ready-made wire format this
// library uses for shipping an API key to an enclave.

const (
	// HpkeKemID is DHKEM(X25519, HKDF-SHA256).
	HpkeKemID = 0x0020
	// HpkeKdfID is HKDF-SHA256.
	HpkeKdfID = 0x0001
	// HpkeEncBytes is the size of an encapsulated key (a serialized X25519
	// public key).
	HpkeEncBytes = X25519KeyBytes
	// HpkeTagBytes is the AEAD tag size; every AEAD here uses 16 bytes.
	HpkeTagBytes = 16

	hpkeModeBase   = 0x00
	hpkeNh         = 32 // Nh for HKDF-SHA256
	hpkeNsecret    = 32 // Nsecret for DHKEM(X25519, ...)
	hpkeNonceBytes = 12 // Nn for every AEAD registered so far
)

var (
	hpkeV1      = []byte("HPKE-v1")
	hpkeKemSuID = concatBytes([]byte("KEM"), i2osp(HpkeKemID, 2))
)

// HpkeSuite identifies an HPKE ciphersuite. All the suites here share
// DHKEM(X25519, HKDF-SHA256) and HKDF-SHA256 and differ only in the AEAD.
type HpkeSuite struct {
	name   string
	aeadID int
	nk     int
}

// AEADID returns the RFC 9180 AEAD id.
func (s HpkeSuite) AEADID() int { return s.aeadID }

// KeyBytes returns the AEAD key length, Nk.
func (s HpkeSuite) KeyBytes() int { return s.nk }

// NonceBytes returns the AEAD nonce length, Nn (12 for every AEAD here).
func (s HpkeSuite) NonceBytes() int { return hpkeNonceBytes }

func (s HpkeSuite) String() string { return s.name }

var (
	// HpkeX25519Sha256Aes128Gcm is RFC 9180 A.1, the mandatory-to-implement AEAD.
	HpkeX25519Sha256Aes128Gcm = HpkeSuite{"X25519_SHA256_AES128GCM", 0x0001, 16}
	// HpkeX25519Sha256Aes256Gcm is 256-bit AES, for when a key-size policy asks for it.
	HpkeX25519Sha256Aes256Gcm = HpkeSuite{"X25519_SHA256_AES256GCM", 0x0002, 32}
	// HpkeX25519Sha256ChaCha20Poly1305 is RFC 9180 A.2. The default here: no
	// AES-NI dependency for constant time.
	HpkeX25519Sha256ChaCha20Poly1305 = HpkeSuite{"X25519_SHA256_CHACHA20POLY1305", 0x0003, 32}
)

var hpkeSuites = []HpkeSuite{HpkeX25519Sha256Aes128Gcm, HpkeX25519Sha256Aes256Gcm, HpkeX25519Sha256ChaCha20Poly1305}

// HpkeSuiteFromAEADID returns the suite with the given RFC 9180 AEAD id.
func HpkeSuiteFromAEADID(aeadID int) (HpkeSuite, error) {
	for _, s := range hpkeSuites {
		if s.aeadID == aeadID {
			return s, nil
		}
	}
	return HpkeSuite{}, fmt.Errorf("unsupported HPKE AEAD id: 0x%04x", aeadID)
}

// HpkeSealed is the output of Seal: the encapsulated key and the ciphertext.
type HpkeSealed struct {
	Enc        []byte
	Ciphertext []byte
}

// HpkeSeal encrypts plaintext to recipientPublicKey.
//
// info is application context, bound into the key schedule; it must be a
// fixed, purpose-specific string so ciphertexts cannot be replayed into a
// different protocol. aad is additional authenticated data, authenticated
// but not encrypted.
func HpkeSeal(suite HpkeSuite, recipientPublicKey, info, aad, plaintext []byte) (HpkeSealed, error) {
	ephemeral, err := GenerateX25519KeyPair()
	if err != nil {
		return HpkeSealed{}, err
	}
	defer wipeBytes(ephemeral.SecretKey)
	return hpkeSealWithEphemeral(suite, ephemeral.SecretKey, recipientPublicKey, info, aad, plaintext)
}

// HpkeOpen decrypts an HPKE-sealed message.
//
// It returns an error if authentication fails — a corrupt, forged, or
// mis-addressed ciphertext is indistinguishable here.
func HpkeOpen(suite HpkeSuite, recipientSecretKey, enc, info, aad, ciphertext []byte) ([]byte, error) {
	if len(enc) != HpkeEncBytes {
		return nil, fmt.Errorf("enc must be %d bytes", HpkeEncBytes)
	}
	if len(ciphertext) < HpkeTagBytes {
		return nil, errors.New("ciphertext is shorter than the AEAD tag")
	}
	dh, err := X25519DH(recipientSecretKey, enc)
	if err != nil {
		return nil, err
	}
	defer wipeBytes(dh)
	recipientPublicKey, err := X25519PublicKey(recipientSecretKey)
	if err != nil {
		return nil, err
	}
	sharedSecret := hpkeExtractAndExpand(dh, enc, recipientPublicKey)
	defer wipeBytes(sharedSecret)
	ctx := hpkeKeySchedule(suite, sharedSecret, info)
	defer ctx.wipe()
	return hpkeAEAD(suite, false, ctx.key, ctx.baseNonce, aad, ciphertext)
}

// hpkeContext holds the key schedule outputs of RFC 9180 §5.1. Unexported:
// only the RFC vector tests need it (see hpke_test.go).
type hpkeContext struct {
	key            []byte
	baseNonce      []byte
	exporterSecret []byte
}

func (c hpkeContext) wipe() {
	wipeBytes(c.key, c.baseNonce, c.exporterSecret)
}

// hpkeSealWithEphemeral is Seal with a caller-supplied ephemeral key.
// Unexported: the RFC 9180 vectors pin skEm, and outside a test a reused
// ephemeral key would repeat the AEAD nonce.
func hpkeSealWithEphemeral(suite HpkeSuite, ephemeralSecretKey, recipientPublicKey, info, aad, plaintext []byte) (HpkeSealed, error) {
	if len(recipientPublicKey) != X25519KeyBytes {
		return HpkeSealed{}, fmt.Errorf("recipient public key must be %d bytes", X25519KeyBytes)
	}
	enc, err := X25519PublicKey(ephemeralSecretKey)
	if err != nil {
		return HpkeSealed{}, err
	}
	dh, err := X25519DH(ephemeralSecretKey, recipientPublicKey)
	if err != nil {
		return HpkeSealed{}, err
	}
	defer wipeBytes(dh)
	sharedSecret := hpkeExtractAndExpand(dh, enc, recipientPublicKey)
	defer wipeBytes(sharedSecret)
	ctx := hpkeKeySchedule(suite, sharedSecret, info)
	defer ctx.wipe()
	ct, err := hpkeAEAD(suite, true, ctx.key, ctx.baseNonce, aad, plaintext)
	if err != nil {
		return HpkeSealed{}, err
	}
	return HpkeSealed{Enc: enc, Ciphertext: ct}, nil
}

// hpkeExtractAndExpand is DHKEM's ExtractAndExpand (RFC 9180 §4.1), shared by
// Encap and Decap.
func hpkeExtractAndExpand(dh, enc, recipientPublicKey []byte) []byte {
	kemContext := concatBytes(enc, recipientPublicKey)
	eaePrk := hpkeLabeledExtract(hpkeKemSuID, nil, "eae_prk", dh)
	defer wipeBytes(eaePrk)
	return hpkeLabeledExpand(hpkeKemSuID, eaePrk, "shared_secret", kemContext, hpkeNsecret)
}

// hpkeKeySchedule implements KeySchedule for mode_base (RFC 9180 §5.1): psk
// and psk_id are empty.
func hpkeKeySchedule(suite HpkeSuite, sharedSecret, info []byte) hpkeContext {
	suiteID := hpkeSuiteID(suite)
	pskIDHash := hpkeLabeledExtract(suiteID, nil, "psk_id_hash", nil)
	infoHash := hpkeLabeledExtract(suiteID, nil, "info_hash", info)
	keyScheduleContext := concatBytes([]byte{hpkeModeBase}, pskIDHash, infoHash)

	secret := hpkeLabeledExtract(suiteID, sharedSecret, "secret", nil)
	defer wipeBytes(secret)
	return hpkeContext{
		key:            hpkeLabeledExpand(suiteID, secret, "key", keyScheduleContext, suite.KeyBytes()),
		baseNonce:      hpkeLabeledExpand(suiteID, secret, "base_nonce", keyScheduleContext, suite.NonceBytes()),
		exporterSecret: hpkeLabeledExpand(suiteID, secret, "exp", keyScheduleContext, hpkeNh),
	}
}

func hpkeSuiteID(suite HpkeSuite) []byte {
	return concatBytes([]byte("HPKE"), i2osp(HpkeKemID, 2), i2osp(HpkeKdfID, 2), i2osp(suite.aeadID, 2))
}

func hpkeLabeledExtract(suiteID, salt []byte, label string, ikm []byte) []byte {
	return hpkeExtract(salt, concatBytes(hpkeV1, suiteID, []byte(label), ikm))
}

func hpkeLabeledExpand(suiteID, prk []byte, label string, info []byte, length int) []byte {
	return hpkeExpand(prk, concatBytes(i2osp(length, 2), hpkeV1, suiteID, []byte(label), info), length)
}

// hpkeExtract is HKDF-Extract (RFC 5869 §2.2). An empty salt becomes HashLen
// zero bytes, as the RFC specifies — HMAC zero-pads its key, so this is also
// what an empty-key HMAC would produce, but spelling it out keeps every
// language's empty-key handling out of the picture.
func hpkeExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, hpkeNh)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// hpkeExpand is HKDF-Expand (RFC 5869 §2.3).
func hpkeExpand(prk, info []byte, length int) []byte {
	out := make([]byte, length)
	var block []byte
	done := 0
	for counter := 1; done < length; counter++ {
		mac := hmac.New(sha256.New, prk)
		mac.Write(block)
		mac.Write(info)
		mac.Write([]byte{byte(counter)})
		block = mac.Sum(nil)
		take := len(block)
		if length-done < take {
			take = length - done
		}
		copy(out[done:done+take], block[:take])
		done += take
	}
	return out
}

// hpkeAEAD runs the AEAD at sequence number 0, where the nonce is the base
// nonce unchanged (RFC 9180 §5.2 XORs the sequence number in; it is zero
// here). seal selects encrypt (true) vs. decrypt (false).
func hpkeAEAD(suite HpkeSuite, seal bool, key, nonce, aad, input []byte) ([]byte, error) {
	aead, err := hpkeAEADCipher(suite, key)
	if err != nil {
		return nil, err
	}
	if seal {
		return aead.Seal(nil, nonce, input, aad), nil
	}
	out, err := aead.Open(nil, nonce, input, aad)
	if err != nil {
		return nil, errors.New("HPKE open failed: ciphertext is not authentic")
	}
	return out, nil
}

func hpkeAEADCipher(suite HpkeSuite, key []byte) (cipher.AEAD, error) {
	switch suite.aeadID {
	case HpkeX25519Sha256Aes128Gcm.aeadID, HpkeX25519Sha256Aes256Gcm.aeadID:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case HpkeX25519Sha256ChaCha20Poly1305.aeadID:
		return chacha20poly1305.New(key)
	default:
		return nil, fmt.Errorf("unsupported HPKE AEAD id: 0x%04x", suite.aeadID)
	}
}

// ------------------------------------------------------------------ helpers

// i2osp is I2OSP(n, length): big-endian, fixed width.
func i2osp(n, length int) []byte {
	out := make([]byte, length)
	for i := length - 1; i >= 0; i-- {
		out[i] = byte(n >> (8 * (length - 1 - i)))
	}
	return out
}

func concatBytes(parts ...[]byte) []byte {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func wipeBytes(secrets ...[]byte) {
	for _, s := range secrets {
		for i := range s {
			s[i] = 0
		}
	}
}

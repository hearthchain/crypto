package hearth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// ApiKeyEnvelope is the wire format for handing an API key to a recipient
// that published an X25519 public key — typically a confidential VM (Intel
// TDX) that generated the key inside the TD and bound it into its
// attestation report.
//
// The envelope is a thin, self-describing frame around HPKE (hpke.go):
//
//	offset size field
//	0      4    "HKE1"        format magic and version
//	4      2    kem_id        0x0020, DHKEM(X25519, HKDF-SHA256)
//	6      2    kdf_id        0x0001, HKDF-SHA256
//	8      2    aead_id       0x0003 by default, ChaCha20-Poly1305
//	10     8    fingerprint   SHA-256(recipient public key)[0..8]
//	18     2    metadata_len
//	20     m    metadata      key id and expiry, see ApiKeyMetadata
//	20+m   32   enc           the encapsulated key
//	52+m   48   ciphertext    32-byte API key + 16-byte tag
//
// Everything before enc is passed to the AEAD as additional authenticated
// data, so the suite ids, the recipient fingerprint and the metadata are all
// covered by the tag: an envelope cannot be re-labelled with a different key
// id or expiry, and the info string pins it to this protocol so it cannot be
// replayed into another one.
//
// The fingerprint is a routing hint, not a security control — the recipient
// uses it to reject an envelope sealed to a previous boot's key with a clear
// error instead of an authentication failure.
//
// What this does not give you: HPKE base mode does not authenticate the
// sender, and an envelope stays decryptable as long as the recipient's
// private key lives — authorize the delivery request at the transport
// layer, keep the recipient keypair ephemeral per boot, and set an expiry.
// And none of it means anything until the caller has verified the
// attestation quote and checked that the recipient's public key is the one
// bound into REPORTDATA.

// ApiKeyLength is the number of characters in an API key.
const ApiKeyLength = 32

// ApiKeyFingerprintBytes is the number of bytes of SHA-256(public key)
// carried in the header.
const ApiKeyFingerprintBytes = 8

// DefaultApiKeyEnvelopeSuite is ChaCha20-Poly1305: no reliance on the TD
// having usable AES-NI.
var DefaultApiKeyEnvelopeSuite = HpkeX25519Sha256ChaCha20Poly1305

// apiKeyEnvelopeInfo is the HPKE info string. Changing it breaks
// compatibility, by design.
var apiKeyEnvelopeInfo = []byte("hearth-chain/api-key-hpke/v1")

var apiKeyEnvelopeMagic = []byte("HKE1")

const apiKeyEnvelopeHeaderFixedBytes = 20
const apiKeyEnvelopeMaxMetadataBytes = 0xffff

const apiKeyAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// apiKeySampleLimit is the largest multiple of 62 that fits in a byte; above
// it, resample (no modulo bias).
const apiKeySampleLimit = (256 / len(apiKeyAlphabet)) * len(apiKeyAlphabet)

// ApiKeyMetadata is what the envelope claims about the key it carries,
// authenticated by the AEAD tag.
//
// KeyID identifies the API key, 1..255 bytes of UTF-8; it lets the recipient
// tell which key it received without logging the key itself. NotAfter is
// when the key stops being valid, or the zero Time for no expiry. Truncated
// to whole seconds on the wire.
type ApiKeyMetadata struct {
	KeyID    string
	NotAfter time.Time
}

// NewApiKeyMetadata builds metadata with no expiry.
func NewApiKeyMetadata(keyID string) (ApiKeyMetadata, error) {
	return NewApiKeyMetadataWithExpiry(keyID, time.Time{})
}

// NewApiKeyMetadataWithExpiry builds metadata that expires at notAfter (pass
// the zero Time for no expiry).
func NewApiKeyMetadataWithExpiry(keyID string, notAfter time.Time) (ApiKeyMetadata, error) {
	length := len(keyID)
	if length < 1 || length > 255 {
		return ApiKeyMetadata{}, fmt.Errorf("key id must be 1..255 bytes of UTF-8, was %d", length)
	}
	return ApiKeyMetadata{KeyID: keyID, NotAfter: notAfter}, nil
}

func (m ApiKeyMetadata) encode() []byte {
	id := []byte(m.KeyID)
	out := make([]byte, 0, 1+len(id)+8)
	out = append(out, byte(len(id)))
	out = append(out, id...)
	var epoch uint64
	if !m.NotAfter.IsZero() {
		epoch = uint64(m.NotAfter.Unix())
	}
	var epochBytes [8]byte
	binary.BigEndian.PutUint64(epochBytes[:], epoch)
	return append(out, epochBytes[:]...)
}

func decodeApiKeyMetadata(encoded []byte) (ApiKeyMetadata, error) {
	if len(encoded) < 1+8 {
		return ApiKeyMetadata{}, errors.New("truncated envelope metadata")
	}
	length := int(encoded[0])
	if len(encoded) != 1+length+8 {
		return ApiKeyMetadata{}, errors.New("envelope metadata length mismatch")
	}
	id := encoded[1 : 1+length]
	epoch := binary.BigEndian.Uint64(encoded[1+length:])
	m := ApiKeyMetadata{KeyID: string(id)}
	if epoch != 0 {
		m.NotAfter = time.Unix(int64(epoch), 0).UTC()
	}
	return m, nil
}

// OpenedApiKey is a decrypted envelope. Call Wipe once the key has been used.
type OpenedApiKey struct {
	ApiKey   []byte // ASCII characters, ApiKeyLength long
	Metadata ApiKeyMetadata
}

// Wipe zeroes the recovered API key bytes.
func (o OpenedApiKey) Wipe() {
	for i := range o.ApiKey {
		o.ApiKey[i] = 0
	}
}

// SealApiKey seals an API key with the default suite.
//
// The caller must already have verified that recipientPublicKey belongs to
// the enclave it expects; this function cannot check that.
func SealApiKey(recipientPublicKey, apiKey []byte, metadata ApiKeyMetadata) ([]byte, error) {
	return SealApiKeyWithSuite(recipientPublicKey, apiKey, metadata, DefaultApiKeyEnvelopeSuite)
}

// SealApiKeyWithSuite seals an API key to recipientPublicKey with the given
// suite.
//
// It returns an error if apiKey is not ApiKeyLength alphanumeric ASCII
// characters.
func SealApiKeyWithSuite(recipientPublicKey, apiKey []byte, metadata ApiKeyMetadata, suite HpkeSuite) ([]byte, error) {
	if err := validateApiKey(apiKey); err != nil {
		return nil, err
	}
	fingerprint, err := apiKeyFingerprint(recipientPublicKey)
	if err != nil {
		return nil, err
	}
	header, err := apiKeyEnvelopeHeader(suite, fingerprint, metadata.encode())
	if err != nil {
		return nil, err
	}
	sealed, err := HpkeSeal(suite, recipientPublicKey, apiKeyEnvelopeInfo, header, apiKey)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(header)+len(sealed.Enc)+len(sealed.Ciphertext))
	out = append(out, header...)
	out = append(out, sealed.Enc...)
	out = append(out, sealed.Ciphertext...)
	return out, nil
}

// OpenApiKey opens an envelope, rejecting one that has expired as of now.
func OpenApiKey(recipientSecretKey, envelope []byte) (OpenedApiKey, error) {
	return OpenApiKeyAt(recipientSecretKey, envelope, time.Now())
}

// OpenApiKeyAt opens an envelope, judging ApiKeyMetadata.NotAfter against
// now.
//
// It returns an error if the envelope is malformed, sealed to a different
// recipient key, not authentic, or expired.
func OpenApiKeyAt(recipientSecretKey, envelope []byte, now time.Time) (OpenedApiKey, error) {
	if len(envelope) < apiKeyEnvelopeHeaderFixedBytes {
		return OpenedApiKey{}, errors.New("truncated envelope")
	}
	magic := envelope[0:4]
	if string(magic) != string(apiKeyEnvelopeMagic) {
		return OpenedApiKey{}, errors.New("not an API key envelope")
	}
	kemID := int(binary.BigEndian.Uint16(envelope[4:6]))
	kdfID := int(binary.BigEndian.Uint16(envelope[6:8]))
	aeadID := int(binary.BigEndian.Uint16(envelope[8:10]))
	if kemID != HpkeKemID || kdfID != HpkeKdfID {
		return OpenedApiKey{}, fmt.Errorf("unsupported HPKE suite: kem=0x%04x kdf=0x%04x", kemID, kdfID)
	}
	suite, err := HpkeSuiteFromAEADID(aeadID)
	if err != nil {
		return OpenedApiKey{}, err
	}

	fingerprint := envelope[10:18]
	metadataLength := int(binary.BigEndian.Uint16(envelope[18:20]))

	ciphertextLength := ApiKeyLength + HpkeTagBytes
	expected := apiKeyEnvelopeHeaderFixedBytes + metadataLength + HpkeEncBytes + ciphertextLength
	if len(envelope) != expected {
		return OpenedApiKey{}, fmt.Errorf("envelope length mismatch: expected %d bytes, got %d", expected, len(envelope))
	}
	metadataBytes := envelope[20 : 20+metadataLength]
	enc := envelope[20+metadataLength : 20+metadataLength+HpkeEncBytes]
	ciphertext := envelope[20+metadataLength+HpkeEncBytes:]

	recipientPublicKey, err := X25519PublicKey(recipientSecretKey)
	if err != nil {
		return OpenedApiKey{}, err
	}
	wantFingerprint, err := apiKeyFingerprint(recipientPublicKey)
	if err != nil {
		return OpenedApiKey{}, err
	}
	if string(fingerprint) != string(wantFingerprint) {
		return OpenedApiKey{}, errors.New("envelope is sealed to a different recipient key")
	}

	// Everything before enc is the AAD, so the suite ids, fingerprint and
	// metadata are all covered by the tag.
	header := envelope[:apiKeyEnvelopeHeaderFixedBytes+metadataLength]
	plaintext, err := HpkeOpen(suite, recipientSecretKey, enc, apiKeyEnvelopeInfo, header, ciphertext)
	if err != nil {
		return OpenedApiKey{}, err
	}
	if err := validateApiKey(plaintext); err != nil {
		wipeBytes(plaintext)
		return OpenedApiKey{}, err
	}
	metadata, err := decodeApiKeyMetadata(metadataBytes)
	if err != nil {
		wipeBytes(plaintext)
		return OpenedApiKey{}, err
	}
	if !metadata.NotAfter.IsZero() && !now.Before(metadata.NotAfter) {
		wipeBytes(plaintext)
		return OpenedApiKey{}, fmt.Errorf("envelope expired at %s", metadata.NotAfter)
	}
	return OpenedApiKey{ApiKey: plaintext, Metadata: metadata}, nil
}

// ApiKeyFingerprint returns SHA-256(public key) truncated to
// ApiKeyFingerprintBytes bytes.
func ApiKeyFingerprint(publicKey []byte) ([]byte, error) {
	return apiKeyFingerprint(publicKey)
}

func apiKeyFingerprint(publicKey []byte) ([]byte, error) {
	if len(publicKey) != X25519KeyBytes {
		return nil, fmt.Errorf("public key must be %d bytes", X25519KeyBytes)
	}
	sum := sha256.Sum256(publicKey)
	return sum[:ApiKeyFingerprintBytes], nil
}

// RandomApiKey returns a fresh ApiKeyLength-character alphanumeric API key,
// uniform over the 62-character alphabet (rejection sampling — % 62 on a
// random byte would favour the first 8 characters).
func RandomApiKey() ([]byte, error) {
	return RandomApiKeyFrom(rand.Reader)
}

// RandomApiKeyFrom returns a fresh API key from a caller-supplied source of
// randomness.
func RandomApiKeyFrom(random io.Reader) ([]byte, error) {
	key := make([]byte, ApiKeyLength)
	buf := make([]byte, ApiKeyLength)
	filled := 0
	for filled < ApiKeyLength {
		if _, err := io.ReadFull(random, buf); err != nil {
			return nil, err
		}
		for i := 0; i < len(buf) && filled < ApiKeyLength; i++ {
			sample := int(buf[i])
			if sample < apiKeySampleLimit {
				key[filled] = apiKeyAlphabet[sample%len(apiKeyAlphabet)]
				filled++
			}
		}
	}
	return key, nil
}

func apiKeyEnvelopeHeader(suite HpkeSuite, fingerprint, metadata []byte) ([]byte, error) {
	if len(metadata) > apiKeyEnvelopeMaxMetadataBytes {
		return nil, fmt.Errorf("envelope metadata too long: %d", len(metadata))
	}
	out := make([]byte, 0, apiKeyEnvelopeHeaderFixedBytes+len(metadata))
	out = append(out, apiKeyEnvelopeMagic...)
	out = binary.BigEndian.AppendUint16(out, HpkeKemID)
	out = binary.BigEndian.AppendUint16(out, HpkeKdfID)
	out = binary.BigEndian.AppendUint16(out, uint16(suite.aeadID))
	out = append(out, fingerprint...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(metadata)))
	out = append(out, metadata...)
	return out, nil
}

func validateApiKey(apiKey []byte) error {
	if len(apiKey) != ApiKeyLength {
		return fmt.Errorf("API key must be %d characters", ApiKeyLength)
	}
	for _, c := range apiKey {
		alphanumeric := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !alphanumeric {
			return errors.New("API key must be alphanumeric")
		}
	}
	return nil
}

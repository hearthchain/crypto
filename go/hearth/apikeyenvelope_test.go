package hearth_test

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"hearthchain/hearth"
)

var apiKeyEnvelopeNow = time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
var apiKeyEnvelopeLater = apiKeyEnvelopeNow.Add(time.Hour)

func apiKeyEnvelopeMeta(t *testing.T) hearth.ApiKeyMetadata {
	t.Helper()
	m, err := hearth.NewApiKeyMetadataWithExpiry("prod/ingest-api", apiKeyEnvelopeLater)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func openApiKeyForTest(t *testing.T, recipientSecretKey, envelope []byte) hearth.OpenedApiKey {
	t.Helper()
	opened, err := hearth.OpenApiKeyAt(recipientSecretKey, envelope, apiKeyEnvelopeNow)
	if err != nil {
		t.Fatal(err)
	}
	return opened
}

func TestApiKeyEnvelopeSealOpenRoundTrip(t *testing.T) {
	for _, suite := range []hearth.HpkeSuite{
		hearth.HpkeX25519Sha256Aes128Gcm,
		hearth.HpkeX25519Sha256Aes256Gcm,
		hearth.HpkeX25519Sha256ChaCha20Poly1305,
	} {
		t.Run(suite.String(), func(t *testing.T) {
			recipient, err := hearth.GenerateX25519KeyPair()
			if err != nil {
				t.Fatal(err)
			}
			apiKey, err := hearth.RandomApiKey()
			if err != nil {
				t.Fatal(err)
			}

			envelope, err := hearth.SealApiKeyWithSuite(recipient.PublicKey, apiKey, apiKeyEnvelopeMeta(t), suite)
			if err != nil {
				t.Fatal(err)
			}

			// 20-byte fixed header + metadata + 32-byte enc + 32-byte key + 16-byte tag.
			metadataLength := 1 + len("prod/ingest-api") + 8
			wantLen := 20 + metadataLength + 32 + 48
			if len(envelope) != wantLen {
				t.Errorf("envelope length = %d, want %d", len(envelope), wantLen)
			}

			opened := openApiKeyForTest(t, recipient.SecretKey, envelope)
			if !bytes.Equal(opened.ApiKey, apiKey) {
				t.Errorf("apiKey = %q, want %q", opened.ApiKey, apiKey)
			}
			if opened.Metadata.KeyID != "prod/ingest-api" {
				t.Errorf("keyId = %q", opened.Metadata.KeyID)
			}
			if !opened.Metadata.NotAfter.Equal(apiKeyEnvelopeLater) {
				t.Errorf("notAfter = %v, want %v", opened.Metadata.NotAfter, apiKeyEnvelopeLater)
			}

			opened.Wipe()
			for _, b := range opened.ApiKey {
				if b != 0 {
					t.Fatal("wipe left non-zero bytes")
				}
			}
		})
	}
}

func TestApiKeyEnvelopeHeaderCarriesTheSuiteAndRecipientFingerprint(t *testing.T) {
	recipient, err := hearth.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	apiKey, err := hearth.RandomApiKey()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := hearth.SealApiKey(recipient.PublicKey, apiKey, apiKeyEnvelopeMeta(t))
	if err != nil {
		t.Fatal(err)
	}

	if string(envelope[:4]) != "HKE1" {
		t.Errorf("magic = %q", envelope[:4])
	}
	if got := binary.BigEndian.Uint16(envelope[4:6]); got != hearth.HpkeKemID {
		t.Errorf("kem_id = 0x%04x", got)
	}
	if got := binary.BigEndian.Uint16(envelope[6:8]); got != hearth.HpkeKdfID {
		t.Errorf("kdf_id = 0x%04x", got)
	}
	if got := binary.BigEndian.Uint16(envelope[8:10]); int(got) != hearth.DefaultApiKeyEnvelopeSuite.AEADID() {
		t.Errorf("aead_id = 0x%04x", got)
	}
	fp, err := hearth.ApiKeyFingerprint(recipient.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(envelope[10:18], fp) {
		t.Error("fingerprint mismatch")
	}
}

func TestApiKeyEnvelopeRejectsEnvelopeForAnotherRecipient(t *testing.T) {
	recipient, err := hearth.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	other, err := hearth.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	apiKey, err := hearth.RandomApiKey()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := hearth.SealApiKey(recipient.PublicKey, apiKey, apiKeyEnvelopeMeta(t))
	if err != nil {
		t.Fatal(err)
	}

	_, err = hearth.OpenApiKeyAt(other.SecretKey, envelope, apiKeyEnvelopeNow)
	if err == nil || !strings.Contains(err.Error(), "different recipient key") {
		t.Errorf("err = %v, want 'different recipient key'", err)
	}
}

func TestApiKeyEnvelopeRejectsExpiredEnvelope(t *testing.T) {
	recipient, err := hearth.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	apiKey, err := hearth.RandomApiKey()
	if err != nil {
		t.Fatal(err)
	}
	meta, err := hearth.NewApiKeyMetadataWithExpiry("short-lived", apiKeyEnvelopeNow.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := hearth.SealApiKey(recipient.PublicKey, apiKey, meta)
	if err != nil {
		t.Fatal(err)
	}

	_, err = hearth.OpenApiKeyAt(recipient.SecretKey, envelope, apiKeyEnvelopeNow)
	if err == nil || !strings.HasPrefix(err.Error(), "envelope expired") {
		t.Errorf("err = %v, want prefix 'envelope expired'", err)
	}
}

func TestApiKeyEnvelopeMetadataWithoutExpiryNeverExpires(t *testing.T) {
	recipient, err := hearth.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	apiKey, err := hearth.RandomApiKey()
	if err != nil {
		t.Fatal(err)
	}
	meta, err := hearth.NewApiKeyMetadata("forever")
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := hearth.SealApiKey(recipient.PublicKey, apiKey, meta)
	if err != nil {
		t.Fatal(err)
	}

	opened, err := hearth.OpenApiKeyAt(recipient.SecretKey, envelope, time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !opened.Metadata.NotAfter.IsZero() {
		t.Errorf("notAfter = %v, want zero", opened.Metadata.NotAfter)
	}
}

// Every header byte is AAD, so relabelling the metadata breaks the tag.
func TestApiKeyEnvelopeRejectsTamperedMetadata(t *testing.T) {
	recipient, err := hearth.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	apiKey, err := hearth.RandomApiKey()
	if err != nil {
		t.Fatal(err)
	}
	meta, err := hearth.NewApiKeyMetadataWithExpiry("prod/ingest-api", apiKeyEnvelopeLater)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := hearth.SealApiKey(recipient.PublicKey, apiKey, meta)
	if err != nil {
		t.Fatal(err)
	}

	tampered := append([]byte(nil), envelope...)
	metadataEnd := 20 + 1 + len("prod/ingest-api") + 8
	tampered[metadataEnd-1] ^= 0x01

	_, err = hearth.OpenApiKeyAt(recipient.SecretKey, tampered, apiKeyEnvelopeNow)
	if err == nil || !strings.Contains(err.Error(), "not authentic") {
		t.Errorf("err = %v, want 'not authentic'", err)
	}
}

func TestApiKeyEnvelopeRejectsTamperedCiphertextAndEncapsulatedKey(t *testing.T) {
	recipient, err := hearth.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	apiKey, err := hearth.RandomApiKey()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := hearth.SealApiKey(recipient.PublicKey, apiKey, apiKeyEnvelopeMeta(t))
	if err != nil {
		t.Fatal(err)
	}

	for _, offset := range []int{len(envelope) - 1, len(envelope) - 40, len(envelope) - 60} {
		tampered := append([]byte(nil), envelope...)
		tampered[offset] ^= 0x01
		if _, err := hearth.OpenApiKeyAt(recipient.SecretKey, tampered, apiKeyEnvelopeNow); err == nil {
			t.Errorf("flipping byte %d should not open", offset)
		}
	}
}

func TestApiKeyEnvelopeRejectsMalformedEnvelopes(t *testing.T) {
	recipient, err := hearth.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	apiKey, err := hearth.RandomApiKey()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := hearth.SealApiKey(recipient.PublicKey, apiKey, apiKeyEnvelopeMeta(t))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := hearth.OpenApiKeyAt(recipient.SecretKey, make([]byte, 3), apiKeyEnvelopeNow); err == nil {
		t.Error("expected error for truncated envelope")
	}

	wrongMagic := append([]byte(nil), envelope...)
	wrongMagic[0] = 'X'
	if _, err := hearth.OpenApiKeyAt(recipient.SecretKey, wrongMagic, apiKeyEnvelopeNow); err == nil {
		t.Error("expected error for wrong magic")
	}

	truncated := envelope[:len(envelope)-1]
	if _, err := hearth.OpenApiKeyAt(recipient.SecretKey, truncated, apiKeyEnvelopeNow); err == nil {
		t.Error("expected error for truncated envelope")
	}

	unknownAead := append([]byte(nil), envelope...)
	unknownAead[9] = 0xff
	if _, err := hearth.OpenApiKeyAt(recipient.SecretKey, unknownAead, apiKeyEnvelopeNow); err == nil {
		t.Error("expected error for unknown aead")
	}
}

func TestApiKeyEnvelopeRejectsApiKeysOfTheWrongShape(t *testing.T) {
	recipient, err := hearth.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	meta := apiKeyEnvelopeMeta(t)

	if _, err := hearth.SealApiKey(recipient.PublicKey, []byte("tooshort"), meta); err == nil {
		t.Error("expected error for too-short key")
	}
	if _, err := hearth.SealApiKey(recipient.PublicKey, []byte("0123456789012345678901234567890!"), meta); err == nil {
		t.Error("expected error for non-alphanumeric key")
	}
}

func TestApiKeyMetadataRejectsEmptyOrOversizedKeyId(t *testing.T) {
	if _, err := hearth.NewApiKeyMetadata(""); err == nil {
		t.Error("expected error for empty key id")
	}
	if _, err := hearth.NewApiKeyMetadata(strings.Repeat("k", 256)); err == nil {
		t.Error("expected error for oversized key id")
	}
}

func TestRandomApiKeyIsAlphanumericAndCoversTheAlphabet(t *testing.T) {
	seen := map[byte]bool{}
	for i := 0; i < 200; i++ {
		key, err := hearth.RandomApiKey()
		if err != nil {
			t.Fatal(err)
		}
		if len(key) != hearth.ApiKeyLength {
			t.Fatalf("len = %d", len(key))
		}
		for _, c := range key {
			alnum := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
			if !alnum {
				t.Fatalf("not ASCII alphanumeric: %q", c)
			}
			seen[c] = true
		}
	}
	// 6400 draws over a 62-character alphabet: every character should appear.
	if len(seen) != 62 {
		t.Errorf("seen %d distinct characters, want 62", len(seen))
	}
}

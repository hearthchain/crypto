// Command hpke-example delivers an API key to a confidential VM: the TD
// publishes an X25519 public key bound into its attestation report, the
// client seals the key to it with HPKE, and only the TD can open it.
//
// Usage:
//
//	go run ./cmd/hpke-example
package main

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"time"

	"hearthchain/hearth"
)

// reportDataContext is what the TD must place in the 64-byte REPORTDATA field
// of its quote.
var reportDataContext = []byte("hearth-chain/tdx-hpke/v1")

func section(title string) {
	fmt.Printf("\n== %s ==\n", title)
}

func failureOf(action func() error) string {
	if err := action(); err != nil {
		return "rejected: " + err.Error()
	}
	return "OPENED — this should not happen"
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func main() {
	section("1) Inside the TD: generate the recipient keypair, bind it to the quote")
	// In a real TD this keypair is generated at boot and never leaves the
	// enclave; the private key is not persisted anywhere.
	enclave := must(hearth.GenerateX25519KeyPair())
	reportData := sha512.Sum512(append(append([]byte(nil), reportDataContext...), enclave.PublicKey...))
	fmt.Printf("public key (X25519, 32 B): %s\n", hex.EncodeToString(enclave.PublicKey))
	fmt.Printf("REPORTDATA  (SHA-512, 64 B): %s\n", hex.EncodeToString(reportData[:]))
	fmt.Println("  the TD puts this in its quote; the client recomputes it from the")
	fmt.Println("  public key it was handed and compares — that is the binding.")

	section("2) On the client: verify the quote, then seal the API key")
	fmt.Println("(quote verification is out of scope here — check the signature chain,")
	fmt.Println(" the TCB status, MRTD/RTMR, and that REPORTDATA matches the line above)")

	apiKey := must(hearth.RandomApiKey())
	metadata := must(hearth.NewApiKeyMetadataWithExpiry("prod/ingest-api", time.Now().Add(24*time.Hour).Truncate(time.Second)))
	envelope := must(hearth.SealApiKey(enclave.PublicKey, apiKey, metadata))

	fmt.Printf("api key      : %s\n", apiKey)
	fmt.Printf("key id       : %s\n", metadata.KeyID)
	fmt.Printf("expires      : %s\n", metadata.NotAfter)
	fmt.Printf("suite        : %s (aead 0x%04x)\n", hearth.DefaultApiKeyEnvelopeSuite, hearth.DefaultApiKeyEnvelopeSuite.AEADID())
	fmt.Printf("envelope     : %d bytes\n", len(envelope))
	fmt.Printf("  %s\n", hex.EncodeToString(envelope))

	section("3) Back inside the TD: open the envelope")
	opened := must(hearth.OpenApiKey(enclave.SecretKey, envelope))
	fmt.Printf("recovered    : %s\n", opened.ApiKey)
	fmt.Printf("key id       : %s (authenticated, not encrypted)\n", opened.Metadata.KeyID)
	fmt.Printf("matches      : %t\n", string(opened.ApiKey) == string(apiKey))
	opened.Wipe()

	section("4) What an attacker gets")
	// A different TD (or a replayed public key from another machine) cannot read it.
	impostor := must(hearth.GenerateX25519KeyPair())
	fmt.Printf("wrong recipient key  : %s\n", failureOf(func() error {
		_, err := hearth.OpenApiKey(impostor.SecretKey, envelope)
		return err
	}))

	// The metadata is authenticated, so it cannot be relabelled in flight:
	// flip the last byte of the expiry timestamp, still inside the header.
	relabelled := append([]byte(nil), envelope...)
	metadataEnd := 20 + (int(envelope[18])<<8 | int(envelope[19]))
	relabelled[metadataEnd-1] ^= 0x01
	fmt.Printf("relabelled expiry    : %s\n", failureOf(func() error {
		_, err := hearth.OpenApiKey(enclave.SecretKey, relabelled)
		return err
	}))

	// And so is the ciphertext.
	tampered := append([]byte(nil), envelope...)
	tampered[len(tampered)-1] ^= 0x01
	fmt.Printf("flipped tag byte     : %s\n", failureOf(func() error {
		_, err := hearth.OpenApiKey(enclave.SecretKey, tampered)
		return err
	}))

	// An expired envelope is rejected even though it decrypts correctly.
	staleMeta := must(hearth.NewApiKeyMetadataWithExpiry("prod/ingest-api", time.Now().Add(-time.Second)))
	stale := must(hearth.SealApiKey(enclave.PublicKey, must(hearth.RandomApiKey()), staleMeta))
	fmt.Printf("expired envelope     : %s\n", failureOf(func() error {
		_, err := hearth.OpenApiKey(enclave.SecretKey, stale)
		return err
	}))

	section("5) The raw HPKE layer")
	info := []byte("hearth-chain/example/v1")
	sealed := must(hearth.HpkeSeal(hearth.HpkeX25519Sha256ChaCha20Poly1305, enclave.PublicKey, info, nil, []byte("any payload")))
	fmt.Printf("enc (32 B)   : %s\n", hex.EncodeToString(sealed.Enc))
	fmt.Printf("ciphertext   : %s\n", hex.EncodeToString(sealed.Ciphertext))
	openedPayload := must(hearth.HpkeOpen(hearth.HpkeX25519Sha256ChaCha20Poly1305, enclave.SecretKey, sealed.Enc, info, nil, sealed.Ciphertext))
	fmt.Printf("opened       : %s\n", openedPayload)
	fmt.Println()
}

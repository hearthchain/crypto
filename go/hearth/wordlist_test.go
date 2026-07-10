package hearth

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// Guard against drift: the embedded wordlist must be the official BIP-39 English
// file (its SHA-256 is fixed by the standard).
func TestWordlistMatchesOfficialBip39(t *testing.T) {
	const official = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
	sum := sha256.Sum256([]byte(englishWordlist))
	if got := hex.EncodeToString(sum[:]); got != official {
		t.Fatalf("wordlist drift: got %s want %s", got, official)
	}
}

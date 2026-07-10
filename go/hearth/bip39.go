package hearth

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/text/unicode/norm"
)

//go:embed english.txt
var englishWordlist string

var (
	wordlist  []string
	wordIndex map[string]int
)

func init() {
	wordlist = strings.Fields(englishWordlist)
	wordIndex = make(map[string]int, len(wordlist))
	for i, w := range wordlist {
		wordIndex[w] = i
	}
}

func normalizeNFKD(s string) string { return norm.NFKD.String(s) }

// ValidateMnemonic returns nil for a valid BIP-39 mnemonic, else an error.
func ValidateMnemonic(mnemonic string) error {
	words := strings.Fields(normalizeNFKD(mnemonic))
	n := len(words)
	if n != 12 && n != 15 && n != 18 && n != 21 && n != 24 {
		return fmt.Errorf("word count must be 12/15/18/21/24, got %d", n)
	}
	indices := make([]int, n)
	for i, w := range words {
		idx, ok := wordIndex[w]
		if !ok {
			return fmt.Errorf("unknown word: %q", w)
		}
		indices[i] = idx
	}

	totalBits := n * 11
	checksumBits := totalBits / 33
	entropyBits := totalBits - checksumBits
	bits := make([]int, 0, totalBits)
	for _, idx := range indices {
		for b := 10; b >= 0; b-- {
			bits = append(bits, (idx>>b)&1)
		}
	}
	digest := sha256.Sum256(bitsToBytes(bits[:entropyBits]))
	for i := 0; i < checksumBits; i++ {
		expected := int((digest[i/8] >> (7 - (i % 8))) & 1)
		if bits[entropyBits+i] != expected {
			return errors.New("checksum mismatch")
		}
	}
	return nil
}

// MnemonicToSeed derives the 64-byte BIP-39 seed (PBKDF2-HMAC-SHA512, 2048 iters).
func MnemonicToSeed(mnemonic, passphrase string) []byte {
	password := normalizeNFKD(mnemonic)
	salt := normalizeNFKD("mnemonic" + passphrase)
	seed, err := pbkdf2.Key(sha512.New, password, []byte(salt), 2048, 64)
	if err != nil {
		panic(err)
	}
	return seed
}

func bitsToBytes(bits []int) []byte {
	out := make([]byte, len(bits)/8)
	for i := 0; i < len(bits); i += 8 {
		var b int
		for _, bit := range bits[i : i+8] {
			b = (b << 1) | bit
		}
		out[i/8] = byte(b)
	}
	return out
}

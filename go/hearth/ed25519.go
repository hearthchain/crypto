package hearth

import "errors"

// KeyPair is an Ed25519 keypair derived from a 32-byte seed. The same key backs
// the ECVRF (see ecvrf.go).
type KeyPair struct {
	Seed      []byte // 32-byte SLIP-0010 node key (the RFC 9381 "SK")
	PublicKey []byte
	SecretKey []byte // libsodium's 64-byte expanded form (seed || publicKey)
}

func KeyPairFromSeed(seed []byte) (KeyPair, error) {
	if len(seed) != 32 {
		return KeyPair{}, errors.New("Ed25519 seed must be 32 bytes")
	}
	pk, sk := signSeedKeypair(seed)
	return KeyPair{Seed: clone(seed), PublicKey: pk, SecretKey: sk}, nil
}

func (kp KeyPair) Sign(message []byte) []byte { return signDetached(message, kp.SecretKey) }

func Verify(signature, message, publicKey []byte) bool {
	return verifyDetached(signature, message, publicKey)
}

// secretScalar is the RFC 8032 secret scalar: clamp(SHA-512(seed)[0:32]).
func secretScalar(seed []byte) []byte {
	a := clone(sha512Sum(seed)[:32])
	a[0] &= 0xF8
	a[31] = (a[31] & 0x7F) | 0x40
	return a
}

// noncePrefix is the RFC 8032 nonce prefix: SHA-512(seed)[32:64].
func noncePrefix(seed []byte) []byte {
	return sha512Sum(seed)[32:64]
}

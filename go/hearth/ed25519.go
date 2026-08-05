package hearth

import (
	"bytes"
	"errors"
)

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

// eightLE is the scalar 8, little-endian — the curve's cofactor.
var eightLE = []byte{8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

// identityEncoded is the compressed encoding of the curve's identity element
// (x=0, y=1): 0x01 followed by 31 zero bytes.
var identityEncoded = append([]byte{1}, make([]byte, 31)...)

// isSmallOrder reports whether encoded (a 32-byte compressed Edwards point)
// has order dividing 8 — the identity, or a 2-/4-/8-torsion point. Returns
// false (i.e. "not provably small-order") if encoded isn't a valid point at
// all; Verify's own decoding rejects those separately.
func isSmallOrder(encoded []byte) bool {
	cleared, ok := scalarmultNoclamp(eightLE, encoded)
	return ok && bytes.Equal(cleared, identityEncoded)
}

// Verify checks a detached Ed25519 signature.
//
// A small-order public key (in the limit, the identity point) combined with
// R = the same point and S = 0 satisfies the raw verification equation
// [S]B = R + [k]A for every k — i.e. for every message — which is a universal
// forgery unless the small-order case is rejected explicitly: Go's stdlib
// crypto/ed25519.Verify does not reject it. Rejecting either A or R being
// small-order closes this off.
func Verify(signature, message, publicKey []byte) bool {
	if len(signature) != 64 || len(publicKey) != 32 {
		return false
	}
	if isSmallOrder(publicKey) || isSmallOrder(signature[:32]) {
		return false
	}
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

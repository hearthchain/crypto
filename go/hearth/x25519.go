package hearth

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"io"
)

// X25519 (RFC 7748) over raw 32-byte little-endian keys — the Diffie-Hellman
// half of HPKE's DHKEM (see hpke.go).
//
// This runs on the standard library's crypto/ecdh, which implements X25519 in
// pure Go (constant-time, no cgo) and already rejects the all-zero
// (small-order) DH output that RFC 9180 §7.1.4 requires a KEM to abort on.

// X25519KeyBytes is the size of both a private scalar and a public
// u-coordinate.
const X25519KeyBytes = 32

// X25519KeyPair is an X25519 keypair in raw little-endian form.
type X25519KeyPair struct {
	PublicKey []byte
	SecretKey []byte
}

// GenerateX25519KeyPair returns a fresh keypair drawn from crypto/rand.
func GenerateX25519KeyPair() (X25519KeyPair, error) {
	return GenerateX25519KeyPairFrom(rand.Reader)
}

// GenerateX25519KeyPairFrom returns a fresh keypair from the given source of
// randomness. The secret is 32 uniformly random bytes; X25519 clamps them
// internally, so every draw is a valid scalar.
func GenerateX25519KeyPairFrom(random io.Reader) (X25519KeyPair, error) {
	sk := make([]byte, X25519KeyBytes)
	if _, err := io.ReadFull(random, sk); err != nil {
		return X25519KeyPair{}, err
	}
	pk, err := X25519PublicKey(sk)
	if err != nil {
		return X25519KeyPair{}, err
	}
	return X25519KeyPair{PublicKey: pk, SecretKey: sk}, nil
}

// X25519PublicKey returns the public key for a secret scalar, i.e.
// X25519(sk, 9).
func X25519PublicKey(secretKey []byte) ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(secretKey)
	if err != nil {
		return nil, err
	}
	return priv.PublicKey().Bytes(), nil
}

// X25519DH returns the Diffie-Hellman shared coordinate X25519(sk, pk).
//
// It returns an error if publicKey has small order (an all-zero result),
// which RFC 9180 §7.1.4 requires KEMs to reject.
func X25519DH(secretKey, publicKey []byte) ([]byte, error) {
	if len(secretKey) != X25519KeyBytes {
		return nil, errors.New("X25519 secret key must be 32 bytes")
	}
	if len(publicKey) != X25519KeyBytes {
		return nil, errors.New("X25519 public key must be 32 bytes")
	}
	priv, err := ecdh.X25519().NewPrivateKey(secretKey)
	if err != nil {
		return nil, err
	}
	pub, err := ecdh.X25519().NewPublicKey(publicKey)
	if err != nil {
		return nil, errors.New("X25519: public key has small order")
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		// crypto/ecdh's X25519 already rejects a low-order point (all-zero
		// output) here; re-labelled for a consistent error message.
		return nil, errors.New("X25519: public key has small order")
	}
	return shared, nil
}

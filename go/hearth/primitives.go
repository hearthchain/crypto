package hearth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"errors"

	"filippo.io/edwards25519"
)

// Pure-Go crypto primitives: Ed25519 sign/verify and hashing from the standard
// library, and the edwards25519 group/scalar arithmetic (which stdlib keeps
// internal) from filippo.io/edwards25519 — the same constant-time code the Go
// standard library uses internally. No cgo, no libsodium.
//
// Note on "noclamp": libsodium's *_noclamp multiplies by the raw 256-bit scalar,
// whereas edwards25519.Scalar is always reduced mod L. We reduce the scalar mod
// L first; this is identical because every point we multiply here has order L
// (n*P = (n mod L)*P), so results match the libsodium build byte-for-byte.

// BackendName identifies the crypto backend (for display).
func BackendName() string { return "pure-Go (filippo.io/edwards25519)" }

func sha512Sum(in []byte) []byte {
	h := sha512.Sum512(in)
	return h[:]
}

func sha256Sum(in []byte) []byte {
	h := sha256.Sum256(in)
	return h[:]
}

// signSeedKeypair expands a 32-byte seed into (publicKey[32], secretKey[64]).
func signSeedKeypair(seed []byte) (pk, sk []byte) {
	priv := ed25519.NewKeyFromSeed(seed) // 64 bytes = seed || publicKey
	return clone(priv.Public().(ed25519.PublicKey)), clone(priv)
}

func signDetached(msg, sk []byte) []byte {
	return ed25519.Sign(ed25519.PrivateKey(sk), msg)
}

func verifyDetached(sig, msg, pk []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(pk), msg, sig)
}

// pointAdd adds two compressed points; ok=false if either is not a curve point.
// SetBytes accepts any on-curve canonical encoding (incl. non-prime-order),
// which is exactly what RFC 9381 try-and-increment cofactor clearing needs.
func pointAdd(p, q []byte) ([]byte, bool) {
	pp, err1 := new(edwards25519.Point).SetBytes(p)
	qq, err2 := new(edwards25519.Point).SetBytes(q)
	if err1 != nil || err2 != nil {
		return nil, false
	}
	return new(edwards25519.Point).Add(pp, qq).Bytes(), true
}

func pointSub(p, q []byte) ([]byte, bool) {
	pp, err1 := new(edwards25519.Point).SetBytes(p)
	qq, err2 := new(edwards25519.Point).SetBytes(q)
	if err1 != nil || err2 != nil {
		return nil, false
	}
	return new(edwards25519.Point).Subtract(pp, qq).Bytes(), true
}

// scalarmultNoclamp computes n*p; ok=false if p is not a curve point.
func scalarmultNoclamp(n, p []byte) ([]byte, bool) {
	point, err := new(edwards25519.Point).SetBytes(p)
	if err != nil {
		return nil, false
	}
	return new(edwards25519.Point).ScalarMult(mustReduce(n), point).Bytes(), true
}

func scalarmultBaseNoclamp(n []byte) []byte {
	return new(edwards25519.Point).ScalarBaseMult(mustReduce(n)).Bytes()
}

// scalarMul returns x * y mod L.
func scalarMul(x, y []byte) []byte {
	return new(edwards25519.Scalar).Multiply(mustReduce(x), mustReduce(y)).Bytes()
}

// scalarAdd returns x + y mod L.
func scalarAdd(x, y []byte) []byte {
	return new(edwards25519.Scalar).Add(mustReduce(x), mustReduce(y)).Bytes()
}

// scalarReduce reduces a 64-byte little-endian value mod L to a 32-byte scalar.
func scalarReduce(wide []byte) []byte {
	s, err := new(edwards25519.Scalar).SetUniformBytes(wide)
	if err != nil {
		panic(err)
	}
	return s.Bytes()
}

// reduceScalar interprets a 32-byte little-endian value mod L (zero-extended to
// the 64-byte uniform form). This accepts non-canonical inputs such as the
// clamped secret scalar, which can exceed L.
func reduceScalar(n []byte) (*edwards25519.Scalar, error) {
	if len(n) != 32 {
		return nil, errors.New("scalar must be 32 bytes")
	}
	var wide [64]byte
	copy(wide[:32], n) // little-endian: low 32 = n, high 32 = 0
	return new(edwards25519.Scalar).SetUniformBytes(wide[:])
}

func mustReduce(n []byte) *edwards25519.Scalar {
	s, err := reduceScalar(n)
	if err != nil {
		panic(err)
	}
	return s
}

package hearth

import (
	"bytes"
	"errors"
)

// ECVRF-EDWARDS25519-SHA512-TAI, the RFC 9381 VRF (suite_string = 0x03). Reuses
// the exact Ed25519 key: the VRF secret scalar is clamp(SHA-512(seed)) and the
// VRF public key is the Ed25519 public key. Group/scalar arithmetic runs on the
// pure-Go primitives in primitives.go.

const (
	vrfPtLen    = 32
	vrfCLen     = 16
	vrfProofLen = vrfPtLen + vrfCLen + vrfPtLen // 80
)

var (
	vrfSuite    = []byte{0x03}
	vrfIdentity = append([]byte{0x01}, make([]byte, 31)...)
)

// VRFProof is pi = Gamma(32) || C(16) || S(32).
type VRFProof struct {
	Gamma []byte
	C     []byte
	S     []byte
}

func (p VRFProof) Bytes() []byte { return concat(p.Gamma, p.C, p.S) }

// VRFProve returns (proof, VRF output beta[64]).
func VRFProve(seed, alpha []byte) (VRFProof, []byte, error) {
	x := secretScalar(seed)
	y := scalarmultBaseNoclamp(x) // public key Y = x*B
	h, err := vrfEncodeToCurve(y, alpha)
	if err != nil {
		return VRFProof{}, nil, err
	}
	gamma, ok := scalarmultNoclamp(x, h)
	if !ok {
		return VRFProof{}, nil, errors.New("Gamma = x*H failed")
	}
	k := vrfNonce(seed, h)
	u := scalarmultBaseNoclamp(k) // U = k*B
	v, ok := scalarmultNoclamp(k, h)
	if !ok {
		return VRFProof{}, nil, errors.New("V = k*H failed")
	}
	c := vrfChallenge(y, h, gamma, u, v) // 16 bytes
	c32 := make([]byte, 32)
	copy(c32, c)
	s := scalarAdd(k, scalarMul(c32, x)) // s = k + c*x mod L
	proof := VRFProof{Gamma: gamma, C: c, S: s}
	return proof, vrfProofToHash(proof), nil
}

// VRFVerify returns (beta, true) if the proof is valid, else (nil, false).
func VRFVerify(publicKey, alpha, pi []byte) ([]byte, bool) {
	proof, ok := vrfDecode(pi)
	if !ok {
		return nil, false
	}
	h, err := vrfEncodeToCurve(publicKey, alpha)
	if err != nil {
		return nil, false
	}
	c32 := make([]byte, 32)
	copy(c32, proof.C)
	sB := scalarmultBaseNoclamp(proof.S)
	cY, ok := scalarmultNoclamp(c32, publicKey)
	if !ok {
		return nil, false
	}
	u, ok := pointSub(sB, cY) // U = s*B - c*Y
	if !ok {
		return nil, false
	}
	sH, ok := scalarmultNoclamp(proof.S, h)
	if !ok {
		return nil, false
	}
	cGamma, ok := scalarmultNoclamp(c32, proof.Gamma)
	if !ok {
		return nil, false
	}
	v, ok := pointSub(sH, cGamma) // V = s*H - c*Gamma
	if !ok {
		return nil, false
	}
	if !bytes.Equal(vrfChallenge(publicKey, h, proof.Gamma, u, v), proof.C) {
		return nil, false
	}
	return vrfProofToHash(proof), true
}

// vrfProofToHash: beta = SHA-512(suite || 0x03 || point_to_string(8*Gamma) || 0x00).
func vrfProofToHash(proof VRFProof) []byte {
	gamma8, ok := vrfCofactorClear(proof.Gamma)
	if !ok {
		panic("8*Gamma failed")
	}
	return sha512Sum(concat(vrfSuite, []byte{0x03}, gamma8, []byte{0x00}))
}

func vrfDecode(pi []byte) (VRFProof, bool) {
	if len(pi) != vrfProofLen {
		return VRFProof{}, false
	}
	return VRFProof{
		Gamma: pi[:vrfPtLen],
		C:     pi[vrfPtLen : vrfPtLen+vrfCLen],
		S:     pi[vrfPtLen+vrfCLen:],
	}, true
}

// vrfEncodeToCurve is ECVRF_encode_to_curve_try_and_increment (RFC 9381 5.4.1.1).
func vrfEncodeToCurve(pkString, alpha []byte) ([]byte, error) {
	for ctr := 0; ctr < 256; ctr++ {
		hashString := sha512Sum(concat(vrfSuite, []byte{0x01}, pkString, alpha, []byte{byte(ctr)}, []byte{0x00}))
		candidate := hashString[:vrfPtLen] // string_to_point(first 32 bytes)
		if cleared, ok := vrfCofactorClear(candidate); ok && !bytes.Equal(cleared, vrfIdentity) {
			return cleared, nil
		}
	}
	return nil, errors.New("encode_to_curve: no valid point found")
}

// vrfCofactorClear multiplies a compressed point by cofactor 8 via three
// doublings (on-curve check only). Returns ok=false if it is not a curve point.
func vrfCofactorClear(p []byte) ([]byte, bool) {
	p2, ok := pointAdd(p, p)
	if !ok {
		return nil, false
	}
	p4, ok := pointAdd(p2, p2)
	if !ok {
		return nil, false
	}
	return pointAdd(p4, p4)
}

// vrfNonce is ECVRF_nonce_generation_RFC8032 (RFC 9381 5.4.2.2).
func vrfNonce(seed, hString []byte) []byte {
	return scalarReduce(sha512Sum(concat(noncePrefix(seed), hString)))
}

// vrfChallenge is ECVRF_challenge_generation (RFC 9381 5.4.3): first 16 bytes.
func vrfChallenge(y, h, gamma, u, v []byte) []byte {
	return sha512Sum(concat(vrfSuite, []byte{0x02}, y, h, gamma, u, v, []byte{0x00}))[:vrfCLen]
}

func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

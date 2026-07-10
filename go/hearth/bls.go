package hearth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// BLS12-381 key derivation per EIP-2333 (key generation) and EIP-2334 (paths).
// Only derivation is implemented — pure HKDF-SHA-256 + SHA-256 + mod r, no
// pairing library. Unlike SLIP-0010, EIP-2333 has no hardened/non-hardened
// distinction: every child uses the parent secret key (hardened-equivalent),
// and paths carry no "'" marker.

// BLSPurpose is the EIP-2334 purpose (the curve id).
const BLSPurpose = 12381

const (
	lamportChunks = 255
	sha256Len     = 32
)

var (
	blsR, _       = new(big.Int).SetString("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10)
	blsKeygenSalt = []byte("BLS-SIG-KEYGEN-SALT-")
)

// BLSDeriveMasterSK returns the master secret key (32-byte big-endian scalar).
func BLSDeriveMasterSK(seed []byte) ([]byte, error) {
	if len(seed) < 32 {
		return nil, errors.New("EIP-2333 seed must be at least 32 bytes")
	}
	return hkdfModR(seed, nil), nil
}

// BLSDeriveChildSK does one child derivation step. index is a uint32.
func BLSDeriveChildSK(parentSK []byte, index uint32) []byte {
	return hkdfModR(parentSKToLamportPK(parentSK, index), nil)
}

// BLSDerivePath derives along an EIP-2334 path such as "m/12381/9381/0/0".
func BLSDerivePath(seed []byte, path string) ([]byte, error) {
	indices, err := BLSParsePath(path)
	if err != nil {
		return nil, err
	}
	sk, err := BLSDeriveMasterSK(seed)
	if err != nil {
		return nil, err
	}
	for _, idx := range indices {
		sk = BLSDeriveChildSK(sk, idx)
	}
	return sk, nil
}

func BLSParsePath(path string) ([]uint32, error) {
	t := strings.TrimSpace(path)
	if t != "m" && !strings.HasPrefix(t, "m/") {
		return nil, fmt.Errorf("path must start with 'm': %s", path)
	}
	if t == "m" {
		return nil, nil
	}
	parts := strings.Split(t[2:], "/")
	out := make([]uint32, len(parts))
	for i, raw := range parts {
		if strings.Contains(raw, "'") {
			return nil, fmt.Errorf("BLS (EIP-2333) has no hardened notation; drop the ' in %q", raw)
		}
		n, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("index out of uint32 range: %s", raw)
		}
		out[i] = uint32(n)
	}
	return out, nil
}

// --- EIP-2333 internals --------------------------------------------------

func hkdfModR(ikm, keyInfo []byte) []byte {
	const l = 48 // ceil((3 * ceil(log2(r))) / 16)
	salt := blsKeygenSalt
	sk := new(big.Int)
	for sk.Sign() == 0 {
		h := sha256.Sum256(salt)
		salt = h[:]
		prk := hmacSHA256(salt, append(clone(ikm), 0x00)) // HKDF-Extract(salt, IKM || I2OSP(0,1))
		info := append(clone(keyInfo), byte(l>>8), byte(l))
		okm := hkdfExpand(prk, info, l)
		sk.Mod(new(big.Int).SetBytes(okm), blsR)
	}
	return leftPad(sk.Bytes(), 32)
}

func parentSKToLamportPK(parentSK []byte, index uint32) []byte {
	var salt [4]byte
	binary.BigEndian.PutUint32(salt[:], index)
	ikm := leftPad(parentSK, 32)
	notIKM := make([]byte, len(ikm))
	for i, b := range ikm {
		notIKM[i] = ^b
	}
	buf := make([]byte, 0, 2*lamportChunks*sha256Len)
	for _, chunk := range ikmToLamportSK(salt[:], ikm) {
		h := sha256.Sum256(chunk)
		buf = append(buf, h[:]...)
	}
	for _, chunk := range ikmToLamportSK(salt[:], notIKM) {
		h := sha256.Sum256(chunk)
		buf = append(buf, h[:]...)
	}
	h := sha256.Sum256(buf)
	return h[:]
}

func ikmToLamportSK(salt, ikm []byte) [][]byte {
	okm := hkdfExpand(hmacSHA256(salt, ikm), nil, lamportChunks*sha256Len)
	chunks := make([][]byte, lamportChunks)
	for i := 0; i < lamportChunks; i++ {
		chunks[i] = okm[i*sha256Len : (i+1)*sha256Len]
	}
	return chunks
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// hkdfExpand is RFC 5869 HKDF-Expand with HMAC-SHA-256 (length <= 255*32).
func hkdfExpand(prk, info []byte, length int) []byte {
	out := make([]byte, 0, length)
	var t []byte
	for counter := byte(1); len(out) < length; counter++ {
		m := hmac.New(sha256.New, prk)
		m.Write(t)
		m.Write(info)
		m.Write([]byte{counter})
		t = m.Sum(nil)
		out = append(out, t...)
	}
	return out[:length]
}

func leftPad(b []byte, length int) []byte {
	if len(b) >= length {
		return b
	}
	out := make([]byte, length)
	copy(out[length-len(b):], b)
	return out
}

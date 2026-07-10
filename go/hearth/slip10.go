package hearth

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

const hardened = 0x80000000

// Slip10Node is a SLIP-0010 ed25519 node (hardened-only derivation).
type Slip10Node struct {
	PrivateKey []byte
	ChainCode  []byte
}

func hmacSHA512(key, data []byte) []byte {
	m := hmac.New(sha512.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func Slip10Master(seed []byte) Slip10Node {
	i := hmacSHA512([]byte("ed25519 seed"), seed)
	return Slip10Node{PrivateKey: clone(i[:32]), ChainCode: clone(i[32:])}
}

// Slip10DeriveChild does one hardened child step (the hardened bit is added).
func Slip10DeriveChild(parent Slip10Node, index uint32) Slip10Node {
	var idx [4]byte
	binary.BigEndian.PutUint32(idx[:], index|hardened)
	data := make([]byte, 0, 1+32+4)
	data = append(data, 0x00)
	data = append(data, parent.PrivateKey...)
	data = append(data, idx[:]...)
	i := hmacSHA512(parent.ChainCode, data)
	return Slip10Node{PrivateKey: clone(i[:32]), ChainCode: clone(i[32:])}
}

// Slip10DerivePath derives along a path such as "m/44'/9381'/0'/0'/0'".
func Slip10DerivePath(seed []byte, path string) (Slip10Node, error) {
	indices, err := parseHardenedPath(path)
	if err != nil {
		return Slip10Node{}, err
	}
	node := Slip10Master(seed)
	for _, idx := range indices {
		node = Slip10DeriveChild(node, idx)
	}
	return node, nil
}

func parseHardenedPath(path string) ([]uint32, error) {
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
		n, err := strconv.ParseUint(strings.TrimRight(raw, "'hH"), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("bad path segment: %q", raw)
		}
		if n >= hardened {
			return nil, fmt.Errorf("index out of range: %s", raw)
		}
		out[i] = uint32(n)
	}
	return out, nil
}

func clone(b []byte) []byte { return append([]byte(nil), b...) }

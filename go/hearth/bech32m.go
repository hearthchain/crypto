package hearth

import "strings"

// Bech32m encoder/decoder (BIP-350), checksum constant 0x2bc830a3.

const (
	bech32mCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	bech32mConst   = 0x2bc830a3
)

var bech32mGen = [5]int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

func Bech32mEncode(hrp string, data []byte) string {
	values := convertBits(bytesToInts(data), 8, 5, true)
	if values == nil {
		panic("cannot regroup payload bits")
	}
	values = append(values, bech32mCreateChecksum(hrp, values)...)
	var sb strings.Builder
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, d := range values {
		sb.WriteByte(bech32mCharset[d])
	}
	return sb.String()
}

// Bech32mDecodeRaw verifies structure + checksum only, returning the hrp and the
// raw 5-bit data groups (checksum stripped). ok=false on any error.
func Bech32mDecodeRaw(s string) (hrp string, data []int, ok bool) {
	if s != strings.ToLower(s) && s != strings.ToUpper(s) {
		return "", nil, false
	}
	lower := strings.ToLower(s)
	pos := strings.LastIndex(lower, "1")
	if pos < 1 || len(lower)-pos-1 < 6 {
		return "", nil, false
	}
	hrp, dataPart := lower[:pos], lower[pos+1:]
	values := make([]int, len(dataPart))
	for i := 0; i < len(dataPart); i++ {
		idx := strings.IndexByte(bech32mCharset, dataPart[i])
		if idx < 0 {
			return "", nil, false
		}
		values[i] = idx
	}
	if bech32mPolymod(append(bech32mHRPExpand(hrp), values...)) != bech32mConst {
		return "", nil, false
	}
	return hrp, values[:len(values)-6], true
}

// Bech32mDecode decodes into (hrp, payload bytes) — the byte-aligned form.
func Bech32mDecode(s string) (hrp string, data []byte, ok bool) {
	h, values, ok := Bech32mDecodeRaw(s)
	if !ok {
		return "", nil, false
	}
	bits := convertBits(values, 5, 8, false)
	if bits == nil {
		return "", nil, false
	}
	return h, intsToBytes(bits), true
}

// --- internals -----------------------------------------------------------

func bech32mPolymod(values []int) int {
	chk := 1
	for _, v := range values {
		b := chk >> 25
		chk = ((chk & 0x1ffffff) << 5) ^ v
		for i := 0; i < 5; i++ {
			if (b>>i)&1 == 1 {
				chk ^= bech32mGen[i]
			}
		}
	}
	return chk
}

func bech32mHRPExpand(hrp string) []int {
	out := make([]int, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, int(hrp[i])>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, int(hrp[i])&31)
	}
	return out
}

func bech32mCreateChecksum(hrp string, data []int) []int {
	values := append(append(bech32mHRPExpand(hrp), data...), 0, 0, 0, 0, 0, 0)
	pm := bech32mPolymod(values) ^ bech32mConst
	out := make([]int, 6)
	for i := 0; i < 6; i++ {
		out[i] = (pm >> (5 * (5 - i))) & 31
	}
	return out
}

// convertBits regroups a bit stream; returns nil on failure (a valid empty
// result is a non-nil empty slice).
func convertBits(data []int, from, to int, pad bool) []int {
	acc, bits, maxv := 0, 0, (1<<to)-1
	out := []int{}
	for _, value := range data {
		if value < 0 || (value>>from) != 0 {
			return nil
		}
		acc = (acc << from) | value
		bits += from
		for bits >= to {
			bits -= to
			out = append(out, (acc>>bits)&maxv)
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, (acc<<(to-bits))&maxv)
		}
	} else if bits >= from || ((acc<<(to-bits))&maxv) != 0 {
		return nil
	}
	return out
}

func bytesToInts(b []byte) []int {
	out := make([]int, len(b))
	for i, v := range b {
		out[i] = int(v)
	}
	return out
}

func intsToBytes(vals []int) []byte {
	out := make([]byte, len(vals))
	for i, v := range vals {
		out[i] = byte(v)
	}
	return out
}

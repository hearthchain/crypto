package hearth

import "errors"

// Account addresses: Bech32m(hrp, versionByte || SHA-256(publicKey)[0:20]).
// The per-network HRP is a UX guard against sending to the wrong network; it is
// not replay protection (that belongs in the signed transaction).

const (
	ed25519Version = 0x00
	addrHashLen    = 20
)

// Network is the address network (mainnet / testnet).
type Network int

const (
	Testnet Network = iota
	Mainnet
)

func (n Network) HRP() string {
	switch n {
	case Testnet:
		return "hrtht"
	case Mainnet:
		return "hrthm"
	default:
		return ""
	}
}

func networkByHRP(hrp string) (Network, bool) {
	switch hrp {
	case "hrtht":
		return Testnet, true
	case "hrthm":
		return Mainnet, true
	default:
		return 0, false
	}
}

// Address is a decoded address.
type Address struct {
	Network Network
	Hash    []byte
	Version byte
}

func (a Address) String() string {
	return Bech32mEncode(a.Network.HRP(), append([]byte{a.Version}, a.Hash...))
}

func AddressFromPublicKey(publicKey []byte, network Network) (string, error) {
	if len(publicKey) != 32 {
		return "", errors.New("public key must be 32 bytes")
	}
	digest := sha256Sum(publicKey)[:addrHashLen]
	return Bech32mEncode(network.HRP(), append([]byte{ed25519Version}, digest...)), nil
}

func ParseAddress(s string) (*Address, bool) {
	hrp, payload, ok := Bech32mDecode(s)
	if !ok {
		return nil, false
	}
	network, ok := networkByHRP(hrp)
	if !ok || len(payload) != addrHashLen+1 || payload[0] != ed25519Version {
		return nil, false
	}
	return &Address{Network: network, Hash: payload[1:], Version: payload[0]}, true
}

func ParseAddressFor(s string, expected Network) (*Address, bool) {
	a, ok := ParseAddress(s)
	if !ok || a.Network != expected {
		return nil, false
	}
	return a, true
}

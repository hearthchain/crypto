package hearth

import "fmt"

// The three role keys, derived from one BIP-39 seed at separate paths. Signing
// and VRF keys use different hardened SLIP-0010 role indices so their secret
// scalars are unrelated (removing the EdDSA/ECVRF shared-key risk). BLS finality
// keys live in their own EIP-2333 tree (different curve).

const (
	keytreeCoinType = 9381 // placeholder — register a SLIP-0044 value
	roleSigning     = 0
	roleVRF         = 1
)

func SigningPath(account uint32) string {
	return fmt.Sprintf("m/44'/%d'/%d'/%d'/0'", keytreeCoinType, account, roleSigning)
}

func VRFPath(account uint32) string {
	return fmt.Sprintf("m/44'/%d'/%d'/%d'/0'", keytreeCoinType, account, roleVRF)
}

func BLSPath(account uint32) string {
	return fmt.Sprintf("m/%d/%d/%d/0", BLSPurpose, keytreeCoinType, account)
}

// SigningKey is the ed25519 transaction-signing keypair.
func SigningKey(seed []byte, account uint32) (KeyPair, error) {
	node, err := Slip10DerivePath(seed, SigningPath(account))
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPairFromSeed(node.PrivateKey)
}

// VRFKey is the ed25519 VRF keypair (its Seed feeds VRFProve; PublicKey is the
// VRF public key to register).
func VRFKey(seed []byte, account uint32) (KeyPair, error) {
	node, err := Slip10DerivePath(seed, VRFPath(account))
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPairFromSeed(node.PrivateKey)
}

// BLSSecretKey is the BLS12-381 finality secret key (32-byte big-endian scalar).
func BLSSecretKey(seed []byte, account uint32) ([]byte, error) {
	return BLSDerivePath(seed, BLSPath(account))
}

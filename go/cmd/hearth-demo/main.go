// Command hearth-demo is the sample app for the hearth-chain crypto stack (Go /
// libsodium). It derives distinct signing / VRF / BLS keys from one mnemonic,
// signs and verifies a message, then VRF-proves an alpha and derives beta.
//
// Usage:
//
//	hearth-demo [mnemonic] [messageBase64] [alphaBase64]
package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"

	"hearthchain/hearth"
)

const (
	defaultMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon about"
	account = 0
)

func section(title string) { fmt.Printf("\n== %s ==\n", title) }

func arg(i int, fallback string) string {
	if i < len(os.Args)-1 && os.Args[i+1] != "" {
		return os.Args[i+1]
	}
	return fallback
}

func main() {
	mnemonic := arg(0, defaultMnemonic)
	messageB64 := arg(1, base64.StdEncoding.EncodeToString([]byte("hearth-chain block header")))
	alphaB64 := arg(2, base64.StdEncoding.EncodeToString([]byte("epoch-42-slot-7")))

	section("0) Inputs")
	fmt.Printf("crypto backend : %s\n", hearth.BackendName())
	fmt.Printf("mnemonic       : %s\n", mnemonic)
	if err := hearth.ValidateMnemonic(mnemonic); err != nil {
		fmt.Printf("mnemonic check : INVALID (%v)\n", err)
		os.Exit(1)
	}
	fmt.Println("mnemonic check : VALID (BIP-39 checksum ok)")

	// (1) Derive keys — one mnemonic, separate per-role / per-curve trees
	section("1) Key derivation (one mnemonic -> distinct signing / VRF / BLS keys)")
	seed := hearth.MnemonicToSeed(mnemonic, "")
	signing := must(hearth.SigningKey(seed, account)) // ed25519, SLIP-0010 role 0
	vrf := must(hearth.VRFKey(seed, account))         // ed25519, SLIP-0010 role 1
	blsSk := must(hearth.BLSSecretKey(seed, account)) // BLS12-381, EIP-2333
	signingAddrMain := must(hearth.AddressFromPublicKey(signing.PublicKey, hearth.Mainnet))
	signingAddrTest := must(hearth.AddressFromPublicKey(signing.PublicKey, hearth.Testnet))
	fmt.Printf("BIP-39 seed    : %s\n\n", hex.EncodeToString(seed))
	fmt.Printf("signing path   : %s\n", hearth.SigningPath(account))
	fmt.Printf("signing pubkey : %s\n", hex.EncodeToString(signing.PublicKey))
	fmt.Printf("address (main) : %s\n", signingAddrMain)
	fmt.Printf("address (test) : %s\n\n", signingAddrTest)
	fmt.Printf("VRF path       : %s\n", hearth.VRFPath(account))
	fmt.Printf("VRF pubkey     : %s  (distinct scalar from signing)\n\n", hex.EncodeToString(vrf.PublicKey))
	fmt.Printf("BLS path       : %s  (EIP-2333, no hardened marker)\n", hearth.BLSPath(account))
	fmt.Printf("BLS secret key : %s  (32-byte scalar mod r)\n", hex.EncodeToString(blsSk))

	// (2) Sign a base64 message with the signing key
	section("2) Ed25519 sign (RFC 8032, Ledger-native) - signing key")
	message := must(base64.StdEncoding.DecodeString(messageB64))
	signature := signing.Sign(message)
	fmt.Printf("message (b64)  : %s\n", messageB64)
	fmt.Printf("message (hex)  : %s\n", hex.EncodeToString(message))
	fmt.Printf("signature      : %s  (64 bytes)\n", hex.EncodeToString(signature))

	// (3) Verify the signature
	section("3) Ed25519 verify")
	fmt.Printf("verify         : %s\n", valid(hearth.Verify(signature, message, signing.PublicKey)))
	tampered := append([]byte(nil), message...)
	if len(tampered) > 0 {
		tampered[0] ^= 0x01
	}
	if hearth.Verify(signature, tampered, signing.PublicKey) {
		fmt.Println("verify tampered: VALID (!)")
	} else {
		fmt.Println("verify tampered: INVALID (expected)")
	}

	// (4) VRF sign and derive VRF value with the VRF key
	section("4) ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381) - VRF key")
	alpha := must(base64.StdEncoding.DecodeString(alphaB64))
	proof, beta, err := hearth.VRFProve(vrf.Seed, alpha)
	if err != nil {
		panic(err)
	}
	betaVerify, vrfOK := hearth.VRFVerify(vrf.PublicKey, alpha, proof.Bytes())
	fmt.Printf("alpha (b64)    : %s\n", alphaB64)
	fmt.Printf("alpha (hex)    : %s\n", hex.EncodeToString(alpha))
	fmt.Printf("pi (proof)     : %s  (80 bytes)\n", hex.EncodeToString(proof.Bytes()))
	fmt.Printf("  gamma        : %s\n", hex.EncodeToString(proof.Gamma))
	fmt.Printf("  c            : %s\n", hex.EncodeToString(proof.C))
	fmt.Printf("  s            : %s\n", hex.EncodeToString(proof.S))
	fmt.Printf("beta (VRF out) : %s  (64 bytes)\n", hex.EncodeToString(beta))
	fmt.Printf("vrf verify     : %s\n", valid(vrfOK))
	if vrfOK {
		fmt.Printf("vrf verify beta: %s  (matches: %t)\n", hex.EncodeToString(betaVerify), string(betaVerify) == string(beta))
	}
}

func valid(ok bool) string {
	if ok {
		return "VALID"
	}
	return "INVALID"
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

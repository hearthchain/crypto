# hearth-chain — Go implementation

Go implementation of the hearth-chain crypto foundation. See the
[root README](../README.md) for the language-independent cryptographic design
(schemes, key derivation, addresses, replay protection). This one covers the Go
tooling and layout.

- **Go** 1.26, module `hearthchain`.
- **Pure Go, no cgo.** Ed25519 sign/verify and hashing come from the standard
  library; the edwards25519 group/scalar arithmetic the VRF needs (which stdlib
  keeps internal) comes from [`filippo.io/edwards25519`](https://filippo.io/edwards25519)
  — the same constant-time code the Go standard library uses internally. The
  HMAC-based constructions (PBKDF2, SLIP-0010, HKDF) use the standard library
  (`crypto/pbkdf2`, `crypto/hmac`); BIP-39 NFKD normalization uses `golang.org/x/text`.

## Prerequisites

- Just Go 1.26+. No C toolchain, no libsodium — it builds with `CGO_ENABLED=0`
  and cross-compiles to static binaries.

## Run

```bash
go test ./...          # official RFC 9381 / SLIP-0010 / BIP-39 / EIP-2333 / BIP-350 vectors
go run ./cmd/hearth-demo   # the sample app with a demo mnemonic

# custom inputs: go run ./cmd/hearth-demo <mnemonic> <messageBase64> <alphaBase64>
go run ./cmd/hearth-demo "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" aGVsbG8= d29ybGQ=

go vet ./...           # static checks
gofmt -l hearth cmd    # formatting (empty output = clean)
```

## Layout

```
go.mod                          module hearthchain, go 1.26
hearth/                         package hearth (all crypto)
  primitives.go  pure-Go crypto — stdlib + filippo.io/edwards25519 group ops
  bip39.go       mnemonic validation + PBKDF2 seed (embeds english.txt)
  slip10.go      SLIP-0010 ed25519 hierarchical derivation
  bls.go         BLS12-381 key derivation (EIP-2333 / EIP-2334)
  ed25519.go     keypair from seed, sign/verify, VRF scalar/nonce
  ecvrf.go       RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI
  bech32m.go     BIP-350 codec
  address.go     account addresses + Network
  keytree.go     the three role keys from one seed
  vectors_test.go  official vectors + cross-parity with the Scala/Python builds
cmd/hearth-demo/main.go         the sample app
```

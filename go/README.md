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
- **HPKE (RFC 9180)** (`Hpke*`, `ApiKey*`) for sealing a secret to a published
  public key — see [Sealing a secret to a public key](#sealing-a-secret-to-a-public-key).
  X25519 runs on the standard library's `crypto/ecdh`; AES-GCM on `crypto/aes`
  + `crypto/cipher`; ChaCha20-Poly1305 on `golang.org/x/crypto/chacha20poly1305`
  (same publisher family as the existing `golang.org/x/text` dependency).

## Prerequisites

- Just Go 1.26+. No C toolchain, no libsodium — it builds with `CGO_ENABLED=0`
  and cross-compiles to static binaries.

## Run

```bash
go test ./...          # official RFC 9381 / 9180 / SLIP-0010 / BIP-39 / EIP-2333 / BIP-350 vectors
go run ./cmd/hearth-demo   # the sample app with a demo mnemonic

# custom inputs: go run ./cmd/hearth-demo <mnemonic> <messageBase64> <alphaBase64>
go run ./cmd/hearth-demo "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" aGVsbG8= d29ybGQ=

# HPKE example: seal an API key to an enclave's public key, open it, try to forge it
go run ./cmd/hpke-example

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
  x25519.go      RFC 7748 over raw keys (crypto/ecdh)
  hpke.go        RFC 9180 single-shot seal/open, base mode
  apikeyenvelope.go  the API-key wire format on top of Hpke
  vectors_test.go  official vectors + cross-parity with the other builds
  hpke_test.go     RFC 9180 A.1/A.2 vectors (white-box: unexported key-schedule access)
  apikeyenvelope_test.go  envelope round-trip / tamper / expiry
cmd/hearth-demo/main.go         the sample app
cmd/hpke-example/main.go        seal an API key to an enclave key
```

## Sealing a secret to a public key

`ApiKeyEnvelope` (`apikeyenvelope.go`) covers the case this library was extended
for: shipping a 32-character API key to a confidential VM (Intel TDX) that
generated an X25519 keypair inside the TD and bound the public key into its
attestation report.

```go
// client — after verifying the quote and that REPORTDATA == SHA-512(ctx || pk)
apiKey, _ := hearth.RandomApiKey()
metadata, _ := hearth.NewApiKeyMetadataWithExpiry("prod/ingest-api", time.Now().Add(24*time.Hour))
envelope, _ := hearth.SealApiKey(enclavePublicKey, apiKey, metadata)

// enclave
opened, err := hearth.OpenApiKey(enclaveSecretKey, envelope)
use(opened.ApiKey)
opened.Wipe()
```

Ciphersuite: **DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305**
(0x0020 / 0x0001 / 0x0003), HPKE **base mode**, single-shot. AES-128-GCM and
AES-256-GCM are also available via `hearth.SealApiKeyWithSuite` /
`hearth.HpkeSuiteFromAEADID`. The envelope is 124 bytes for a 15-character key
id: a 20-byte fixed header, the metadata, the 32-byte encapsulated key, and 48
bytes of ciphertext. Everything before the encapsulated key is the AEAD's
additional data, so the suite ids, the recipient fingerprint, the key id and
the expiry are all covered by the tag.

Use `hearth.HpkeSeal`/`hearth.HpkeOpen` directly for any other payload;
`ApiKeyEnvelope` only adds the fixed `info` string, the frame, and the
32-alphanumeric-character check.

**This is only half of the problem.** HPKE gets the key to whoever holds the
private key; it says nothing about *who that is*. The client must verify the
TDX quote — signature chain to Intel's PCS, TCB status, `MRTD`/`RTMR`
measurements — and check that the public key it is about to seal to is the one
hashed into `REPORTDATA`, before calling `SealApiKey`. Base mode also leaves
the sender unauthenticated and the ciphertext replayable for as long as the
recipient's private key lives: authorize delivery at the transport layer, keep
the TD's keypair ephemeral per boot, and set an expiry.

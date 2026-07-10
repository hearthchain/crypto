// Sample app for the hearth-chain crypto stack. Derives distinct signing / VRF /
// BLS keys from one mnemonic, signs and verifies a message, then VRF-proves an
// alpha and derives + verifies the VRF value beta.
//
// Usage: node src/demo.ts [mnemonic] [messageBase64] [alphaBase64]

import { address, bip39, ecvrf, ed25519, hex, keytree } from "./index.ts";

const DEFAULT_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ACCOUNT = 0;

const section = (title: string): void => console.log(`\n== ${title} ==`);
const b64encode = (s: string): string => Buffer.from(s, "utf8").toString("base64");
const b64decode = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "base64"));

function arg(args: string[], i: number, fallback: string): string {
  return args[i] && args[i].length > 0 ? args[i] : fallback;
}

const args = process.argv.slice(2);
const mnemonic = arg(args, 0, DEFAULT_MNEMONIC);
const messageB64 = arg(args, 1, b64encode("hearth-chain block header"));
const alphaB64 = arg(args, 2, b64encode("epoch-42-slot-7"));

section("0) Inputs");
console.log("crypto backend : pure-TypeScript (@noble/curves + @noble/hashes)");
console.log(`mnemonic       : ${mnemonic}`);
const check = bip39.validate(mnemonic);
if (!check.valid) {
  console.log(`mnemonic check : INVALID (${check.reason})`);
  process.exit(1);
}
console.log("mnemonic check : VALID (BIP-39 checksum ok)");

// (1) Derive keys — one mnemonic, separate per-role / per-curve trees
section("1) Key derivation (one mnemonic -> distinct signing / VRF / BLS keys)");
const seed = bip39.toSeed(mnemonic);
const signing = keytree.signingKey(seed, ACCOUNT);
const vrf = keytree.vrfKey(seed, ACCOUNT);
const blsSk = keytree.blsSecretKey(seed, ACCOUNT);
console.log(`BIP-39 seed    : ${hex.encode(seed)}\n`);
console.log(`signing path   : ${keytree.signingPath(ACCOUNT)}`);
console.log(`signing pubkey : ${hex.encode(signing.publicKey)}`);
console.log(`address (main) : ${address.fromPublicKey(signing.publicKey, address.Network.Mainnet)}`);
console.log(`address (test) : ${address.fromPublicKey(signing.publicKey, address.Network.Testnet)}\n`);
console.log(`VRF path       : ${keytree.vrfPath(ACCOUNT)}`);
console.log(`VRF pubkey     : ${hex.encode(vrf.publicKey)}  (distinct scalar from signing)\n`);
console.log(`BLS path       : ${keytree.blsPath(ACCOUNT)}  (EIP-2333, no hardened marker)`);
console.log(`BLS secret key : ${hex.encode(blsSk)}  (32-byte scalar mod r)`);

// (2) Sign a base64 message with the signing key
section("2) Ed25519 sign (RFC 8032, Ledger-native) - signing key");
const message = b64decode(messageB64);
const signature = signing.sign(message);
console.log(`message (b64)  : ${messageB64}`);
console.log(`message (hex)  : ${hex.encode(message)}`);
console.log(`signature      : ${hex.encode(signature)}  (64 bytes)`);

// (3) Verify the signature
section("3) Ed25519 verify");
console.log(`verify         : ${ed25519.verify(signature, message, signing.publicKey) ? "VALID" : "INVALID"}`);
const tampered = message.slice();
if (tampered.length > 0) {
  tampered[0] ^= 0x01;
}
console.log(
  `verify tampered: ${ed25519.verify(signature, tampered, signing.publicKey) ? "VALID (!)" : "INVALID (expected)"}`,
);

// (4) VRF sign and derive VRF value with the VRF key
section("4) ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381) - VRF key");
const alpha = b64decode(alphaB64);
const { proof, beta } = ecvrf.prove(vrf.seed, alpha);
const betaVerify = ecvrf.verify(vrf.publicKey, alpha, proof.bytes());
console.log(`alpha (b64)    : ${alphaB64}`);
console.log(`alpha (hex)    : ${hex.encode(alpha)}`);
console.log(`pi (proof)     : ${hex.encode(proof.bytes())}  (80 bytes)`);
console.log(`  gamma        : ${hex.encode(proof.gamma)}`);
console.log(`  c            : ${hex.encode(proof.c)}`);
console.log(`  s            : ${hex.encode(proof.s)}`);
console.log(`beta (VRF out) : ${hex.encode(beta)}  (64 bytes)`);
console.log(`vrf verify     : ${betaVerify ? "VALID" : "INVALID"}`);
if (betaVerify) {
  console.log(`vrf verify beta: ${hex.encode(betaVerify)}  (matches: ${hex.encode(betaVerify) === hex.encode(beta)})`);
}

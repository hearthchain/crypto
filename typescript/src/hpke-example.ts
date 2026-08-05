// Delivering an API key to a confidential VM: the TD publishes an X25519
// public key bound into its attestation report, the client seals the key to
// it with HPKE, and only the TD can open it.
//
// Usage: node src/hpke-example.ts

import { apikeyenvelope as env, hex, hpke, primitives, x25519 } from "./index.ts";

const REPORT_DATA_CONTEXT = new TextEncoder().encode("hearth-chain/tdx-hpke/v1");

const section = (title: string): void => console.log(`\n== ${title} ==`);

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function failureOf(action: () => void): string {
  try {
    action();
    return "OPENED — this should not happen";
  } catch (e) {
    return `rejected: ${(e as Error).message}`;
  }
}

section("1) Inside the TD: generate the recipient keypair, bind it to the quote");
// In a real TD this keypair is generated at boot and never leaves the
// enclave; the private key is not persisted anywhere.
const enclave = x25519.generateKeypair();
const reportData = primitives.hashSha512(concat(REPORT_DATA_CONTEXT, enclave.publicKey));
console.log(`public key (X25519, 32 B): ${hex.encode(enclave.publicKey)}`);
console.log(`REPORTDATA  (SHA-512, 64 B): ${hex.encode(reportData)}`);
console.log("  the TD puts this in its quote; the client recomputes it from the");
console.log("  public key it was handed and compares — that is the binding.");

section("2) On the client: verify the quote, then seal the API key");
console.log("(quote verification is out of scope here — check the signature chain,");
console.log(" the TCB status, MRTD/RTMR, and that REPORTDATA matches the line above)");

const apiKey = env.randomApiKey();
const apiKeyForDisplay = apiKey.slice();
const notAfter = new Date(Date.now() + 24 * 3600 * 1000);
notAfter.setMilliseconds(0);
const metadata = env.metadata("prod/ingest-api", notAfter);
const envelope = env.seal(enclave.publicKey, apiKey, metadata);

console.log(`api key      : ${new TextDecoder().decode(apiKeyForDisplay)}`);
console.log(`key id       : ${metadata.keyId}`);
console.log(`expires      : ${metadata.notAfter?.toISOString()}`);
console.log(`suite        : ${env.DEFAULT_SUITE} (aead 0x${hpke.aeadId(env.DEFAULT_SUITE).toString(16).padStart(4, "0")})`);
console.log(`envelope     : ${envelope.length} bytes`);
console.log(`  ${hex.encode(envelope)}`);

section("3) Back inside the TD: open the envelope");
const opened = env.open(enclave.secretKey, envelope);
console.log(`recovered    : ${new TextDecoder().decode(opened.apiKey)}`);
console.log(`key id       : ${opened.metadata.keyId} (authenticated, not encrypted)`);
console.log(`matches      : ${hex.encode(opened.apiKey) === hex.encode(apiKeyForDisplay)}`);
env.wipe(opened);

section("4) What an attacker gets");
// A different TD (or a replayed public key from another machine) cannot read it.
const impostor = x25519.generateKeypair();
console.log(`wrong recipient key  : ${failureOf(() => env.open(impostor.secretKey, envelope))}`);

// The metadata is authenticated, so it cannot be relabelled in flight: flip
// the last byte of the expiry timestamp, still inside the header.
const relabelled = envelope.slice();
const metadataEnd = 20 + ((envelope[18] << 8) | envelope[19]);
relabelled[metadataEnd - 1] ^= 0x01;
console.log(`relabelled expiry    : ${failureOf(() => env.open(enclave.secretKey, relabelled))}`);

// And so is the ciphertext.
const tampered = envelope.slice();
tampered[tampered.length - 1] ^= 0x01;
console.log(`flipped tag byte     : ${failureOf(() => env.open(enclave.secretKey, tampered))}`);

// An expired envelope is rejected even though it decrypts correctly.
const stale = env.seal(enclave.publicKey, env.randomApiKey(), env.metadata("prod/ingest-api", new Date(Date.now() - 1000)));
console.log(`expired envelope     : ${failureOf(() => env.open(enclave.secretKey, stale))}`);

section("5) The raw HPKE layer");
const info = new TextEncoder().encode("hearth-chain/example/v1");
const sealed = hpke.seal(
  "X25519_SHA256_CHACHA20POLY1305",
  enclave.publicKey,
  info,
  new Uint8Array(0),
  new TextEncoder().encode("any payload"),
);
console.log(`enc (32 B)   : ${hex.encode(sealed.enc)}`);
console.log(`ciphertext   : ${hex.encode(sealed.ciphertext)}`);
const rawOpened = hpke.open(
  "X25519_SHA256_CHACHA20POLY1305",
  enclave.secretKey,
  sealed.enc,
  info,
  new Uint8Array(0),
  sealed.ciphertext,
);
console.log(`opened       : ${new TextDecoder().decode(rawOpened)}`);
console.log();

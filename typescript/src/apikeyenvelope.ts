// The wire format for handing an API key to a recipient that published an
// X25519 public key — typically a confidential VM (Intel TDX) that generated
// the key inside the TD and bound it into its attestation report.
//
// The envelope is a thin, self-describing frame around ./hpke.ts:
//
//   offset size field
//   0      4    "HKE1"                      format magic and version
//   4      2    kem_id                      0x0020, DHKEM(X25519, HKDF-SHA256)
//   6      2    kdf_id                      0x0001, HKDF-SHA256
//   8      2    aead_id                     0x0003 by default, ChaCha20-Poly1305
//   10     8    fingerprint                 SHA-256(recipient public key)[0..8]
//   18     2    metadata_len
//   20     m    metadata                    key id and expiry, see Metadata
//   20+m   32   enc                         the encapsulated key
//   52+m   48   ciphertext                  32-byte API key + 16-byte tag
//
// Everything before `enc` is passed to the AEAD as additional authenticated
// data, so the suite ids, the recipient fingerprint and the metadata are all
// covered by the tag: an envelope cannot be re-labelled with a different key
// id or expiry, and the `info` string pins it to this protocol so it cannot
// be replayed into another one.
//
// The fingerprint is a routing hint, not a security control — the recipient
// uses it to reject an envelope sealed to a previous boot's key with a clear
// error instead of an authentication failure.
//
// What this does not give you. HPKE base mode does not authenticate the
// sender, and an envelope stays decryptable as long as the recipient's
// private key lives: authorize the delivery request at the transport layer,
// keep the recipient keypair ephemeral per boot, and set Metadata.notAfter.
// And none of it means anything until the caller has verified the
// attestation quote and checked that the recipient's public key is the one
// bound into REPORTDATA.

import { bytesToNumberBE, concatBytes, numberToBytesBE } from "@noble/curves/utils.js";
import { randomBytes } from "@noble/hashes/utils.js";
import * as hpke from "./hpke.ts";
import { hashSha256 } from "./primitives.ts";
import * as x25519 from "./x25519.ts";

/** API keys are exactly this many characters. */
export const API_KEY_LENGTH = 32;

/** ChaCha20-Poly1305: no reliance on the TD having usable AES-NI. */
export const DEFAULT_SUITE: hpke.Suite = "X25519_SHA256_CHACHA20POLY1305";

/** Bytes of SHA-256(public key) carried in the header. */
export const FINGERPRINT_BYTES = 8;

/** The HPKE `info` string. Changing it breaks compatibility, by design. */
const INFO = utf8("hearth-chain/api-key-hpke/v1");

const MAGIC = utf8("HKE1");
const HEADER_FIXED_BYTES = 20;
const MAX_METADATA_BYTES = 0xffff;

const ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
/** Largest multiple of 62 that fits in a byte; above it, resample (no modulo bias). */
const SAMPLE_LIMIT = Math.floor(256 / ALPHANUMERIC.length) * ALPHANUMERIC.length;

/**
 * What the envelope claims about the key it carries, authenticated by the
 * AEAD tag.
 *
 * `keyId` is 1..255 bytes of UTF-8; it lets the recipient tell which key it
 * received without logging the key itself. `notAfter` is when the key stops
 * being valid, or `null` for no expiry — truncated to whole seconds on the
 * wire.
 */
export type Metadata = { keyId: string; notAfter: Date | null };

/** Metadata with no expiry, or an expiry at `notAfter`. */
export function metadata(keyId: string, notAfter: Date | null = null): Metadata {
  const length = utf8(keyId).length;
  if (length < 1 || length > 255) {
    throw new Error(`key id must be 1..255 bytes of UTF-8, was ${length}`);
  }
  return { keyId, notAfter };
}

function encodeMetadata(m: Metadata): Uint8Array {
  const id = utf8(m.keyId);
  const epochSeconds = m.notAfter === null ? 0n : BigInt(Math.floor(m.notAfter.getTime() / 1000));
  return concatBytes(new Uint8Array([id.length]), id, numberToBytesBE(epochSeconds, 8));
}

function decodeMetadata(encoded: Uint8Array): Metadata {
  if (encoded.length < 1 + 8) {
    throw new Error("truncated envelope metadata");
  }
  const length = encoded[0];
  if (encoded.length !== 1 + length + 8) {
    throw new Error("envelope metadata length mismatch");
  }
  const keyId = new TextDecoder().decode(encoded.subarray(1, 1 + length));
  const epochSeconds = bytesToNumberBE(encoded.subarray(1 + length));
  return { keyId, notAfter: epochSeconds === 0n ? null : new Date(Number(epochSeconds) * 1000) };
}

/**
 * A decrypted envelope. Call `wipe()` once the key has been used — `apiKey`
 * is a plain byte buffer so it can be cleared, unlike a JS string.
 */
export type Opened = { apiKey: Uint8Array; metadata: Metadata };

export function wipe(opened: Opened): void {
  opened.apiKey.fill(0);
}

/**
 * Seal an API key to `recipientPublicKey`.
 *
 * The caller must already have verified that this public key belongs to the
 * enclave it expects; this function cannot check that.
 *
 * Throws if the API key is not API_KEY_LENGTH alphanumeric characters.
 */
export function seal(
  recipientPublicKey: Uint8Array,
  apiKey: Uint8Array,
  meta: Metadata,
  suite: hpke.Suite = DEFAULT_SUITE,
): Uint8Array {
  validateApiKey(apiKey);
  const header = buildHeader(suite, fingerprint(recipientPublicKey), encodeMetadata(meta));
  try {
    const sealed = hpke.seal(suite, recipientPublicKey, INFO, header, apiKey);
    return concatBytes(header, sealed.enc, sealed.ciphertext);
  } finally {
    apiKey.fill(0);
  }
}

/**
 * Open an envelope, rejecting one that has expired.
 *
 * @param now the instant to judge Metadata.notAfter against
 * @throws if the envelope is malformed, sealed to a different recipient key,
 *         not authentic, or expired
 */
export function open(recipientSecretKey: Uint8Array, envelope: Uint8Array, now: Date = new Date()): Opened {
  if (envelope.length < HEADER_FIXED_BYTES) {
    throw new Error("truncated envelope");
  }
  const magic = envelope.subarray(0, 4);
  if (!bytesEqual(magic, MAGIC)) {
    throw new Error("not an API key envelope");
  }
  const kemId = readU16(envelope, 4);
  const kdfId = readU16(envelope, 6);
  const aeadIdValue = readU16(envelope, 8);
  if (kemId !== hpke.KEM_ID || kdfId !== hpke.KDF_ID) {
    throw new Error(
      `unsupported HPKE suite: kem=0x${kemId.toString(16).padStart(4, "0")} kdf=0x${kdfId.toString(16).padStart(4, "0")}`,
    );
  }
  const suite = hpke.suiteFromAeadId(aeadIdValue);

  const envFingerprint = envelope.subarray(10, 18);
  const metadataLength = readU16(envelope, 18);

  const ciphertextLength = API_KEY_LENGTH + hpke.TAG_BYTES;
  const expected = HEADER_FIXED_BYTES + metadataLength + hpke.ENC_BYTES + ciphertextLength;
  if (envelope.length !== expected) {
    throw new Error(`envelope length mismatch: expected ${expected} bytes, got ${envelope.length}`);
  }
  const metadataBytes = envelope.subarray(HEADER_FIXED_BYTES, HEADER_FIXED_BYTES + metadataLength);
  const enc = envelope.subarray(HEADER_FIXED_BYTES + metadataLength, HEADER_FIXED_BYTES + metadataLength + hpke.ENC_BYTES);
  const ciphertext = envelope.subarray(HEADER_FIXED_BYTES + metadataLength + hpke.ENC_BYTES);

  const recipientPublicKey = x25519.publicKey(recipientSecretKey);
  if (!bytesEqual(envFingerprint, fingerprint(recipientPublicKey))) {
    throw new Error("envelope is sealed to a different recipient key");
  }

  // Everything before enc is the AAD, so the suite ids, fingerprint and
  // metadata are all covered by the tag.
  const header = envelope.subarray(0, HEADER_FIXED_BYTES + metadataLength);
  const plaintext = hpke.open(suite, recipientSecretKey, enc, INFO, header, ciphertext);
  try {
    validateApiKey(plaintext);
    const meta = decodeMetadata(metadataBytes);
    if (meta.notAfter !== null && now >= meta.notAfter) {
      throw new Error(`envelope expired at ${meta.notAfter.toISOString()}`);
    }
    return { apiKey: plaintext, metadata: meta };
  } catch (e) {
    plaintext.fill(0);
    throw e;
  }
}

/** SHA-256(public key) truncated to FINGERPRINT_BYTES bytes. */
export function fingerprint(publicKey: Uint8Array): Uint8Array {
  if (publicKey.length !== 32) {
    throw new Error("public key must be 32 bytes");
  }
  return hashSha256(publicKey).slice(0, FINGERPRINT_BYTES);
}

/**
 * A fresh API_KEY_LENGTH-character alphanumeric API key, uniform over the
 * 62-character alphabet (rejection sampling — `% 62` on a random byte would
 * favour the first 8 characters).
 */
export function randomApiKey(): Uint8Array {
  const key = new Uint8Array(API_KEY_LENGTH);
  let filled = 0;
  while (filled < API_KEY_LENGTH) {
    const buffer = randomBytes(API_KEY_LENGTH);
    for (let i = 0; i < buffer.length && filled < API_KEY_LENGTH; i++) {
      const sample = buffer[i];
      if (sample < SAMPLE_LIMIT) {
        key[filled++] = ALPHANUMERIC.charCodeAt(sample % ALPHANUMERIC.length);
      }
    }
    buffer.fill(0);
  }
  return key;
}

function buildHeader(suite: hpke.Suite, fp: Uint8Array, metadataBytes: Uint8Array): Uint8Array {
  if (metadataBytes.length > MAX_METADATA_BYTES) {
    throw new Error(`envelope metadata too long: ${metadataBytes.length}`);
  }
  return concatBytes(
    MAGIC,
    numberToBytesBE(BigInt(hpke.KEM_ID), 2),
    numberToBytesBE(BigInt(hpke.KDF_ID), 2),
    numberToBytesBE(BigInt(hpke.aeadId(suite)), 2),
    fp,
    numberToBytesBE(BigInt(metadataBytes.length), 2),
    metadataBytes,
  );
}

function validateApiKey(apiKey: Uint8Array): void {
  if (apiKey.length !== API_KEY_LENGTH) {
    throw new Error(`API key must be ${API_KEY_LENGTH} characters`);
  }
  for (const b of apiKey) {
    const alphanumeric = (b >= 0x30 && b <= 0x39) || (b >= 0x61 && b <= 0x7a) || (b >= 0x41 && b <= 0x5a);
    if (!alphanumeric) {
      throw new Error("API key must be alphanumeric");
    }
  }
}

function readU16(bytes: Uint8Array, offset: number): number {
  return (bytes[offset] << 8) | bytes[offset + 1];
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

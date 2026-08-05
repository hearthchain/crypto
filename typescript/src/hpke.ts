// HPKE (RFC 9180) single-shot public-key encryption, base mode, over
// DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256.
//
// Base mode means the sender is anonymous: anyone holding the recipient's
// public key can seal. That is exactly the shape of "encrypt a secret to a
// public key published by an enclave" — the recipient is authenticated (by
// attestation, out of band), the sender is authorized by the transport.
//
// Only the single-shot Seal/Open of RFC 9180 §6.1 is implemented — one
// message per encapsulation, always at sequence number 0. There is
// deliberately no stateful sender context to reuse, so a nonce can never be
// repeated under one key.
//
// The whole construction runs on @noble: HMAC-SHA256 (HKDF) and AEAD via
// @noble/ciphers, the group operation via ./x25519.ts. Verified against the
// RFC 9180 A.1 and A.2 test vectors.
//
// See ./apikeyenvelope.ts for the ready-made wire format this library uses
// for shipping an API key to an enclave.

import { gcm } from "@noble/ciphers/aes.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { asciiToBytes, concatBytes, numberToBytesBE } from "@noble/curves/utils.js";
import { hmacSha256 } from "./primitives.ts";
import * as x25519 from "./x25519.ts";

/** DHKEM(X25519, HKDF-SHA256). */
export const KEM_ID = 0x0020;

/** HKDF-SHA256. */
export const KDF_ID = 0x0001;

/** Size of an encapsulated key (a serialized X25519 public key). */
export const ENC_BYTES = x25519.KEY_BYTES;

/** Every AEAD here has a 16-byte tag. */
export const TAG_BYTES = 16;

const MODE_BASE = 0x00;
const NH = 32; // Nh for HKDF-SHA256
const NSECRET = 32; // Nsecret for DHKEM(X25519, ...)
const NONCE_BYTES = 12; // Nn for every AEAD registered so far

const HPKE_V1 = asciiToBytes("HPKE-v1");
const KEM_SUITE_ID = concatBytes(asciiToBytes("KEM"), i2osp(KEM_ID, 2));
const EMPTY = new Uint8Array(0);

/**
 * The supported ciphersuites. All share DHKEM(X25519, HKDF-SHA256) and
 * HKDF-SHA256 and differ only in the AEAD.
 */
export type Suite = "X25519_SHA256_AES128GCM" | "X25519_SHA256_AES256GCM" | "X25519_SHA256_CHACHA20POLY1305";

const SUITE_INFO: Record<Suite, { aeadId: number; keyBytes: number }> = {
  /** RFC 9180 A.1. The mandatory-to-implement AEAD. */
  X25519_SHA256_AES128GCM: { aeadId: 0x0001, keyBytes: 16 },
  /** 256-bit AES, for when a key-size policy asks for it. */
  X25519_SHA256_AES256GCM: { aeadId: 0x0002, keyBytes: 32 },
  /** RFC 9180 A.2. The default here: no AES-NI dependency for constant time. */
  X25519_SHA256_CHACHA20POLY1305: { aeadId: 0x0003, keyBytes: 32 },
};

/** The RFC 9180 AEAD id for a suite. */
export function aeadId(suite: Suite): number {
  return SUITE_INFO[suite].aeadId;
}

/** AEAD key length, Nk, for a suite. */
export function keyBytes(suite: Suite): number {
  return SUITE_INFO[suite].keyBytes;
}

/** AEAD nonce length, Nn. 12 for every AEAD registered so far. */
export function nonceBytes(_suite: Suite): number {
  return NONCE_BYTES;
}

/** The suite with this AEAD id. */
export function suiteFromAeadId(id: number): Suite {
  for (const [suite, info] of Object.entries(SUITE_INFO) as [Suite, { aeadId: number; keyBytes: number }][]) {
    if (info.aeadId === id) {
      return suite;
    }
  }
  throw new Error(`unsupported HPKE AEAD id: 0x${id.toString(16).padStart(4, "0")}`);
}

/** The output of seal(): the encapsulated key and the ciphertext. */
export type Sealed = { enc: Uint8Array; ciphertext: Uint8Array };

/**
 * Encrypt `plaintext` to `recipientPublicKey`.
 *
 * @param info application context, bound into the key schedule; it must be a
 *             fixed, purpose-specific string so ciphertexts cannot be
 *             replayed into a different protocol
 * @param aad  additional authenticated data, authenticated but not encrypted
 */
export function seal(
  suite: Suite,
  recipientPublicKey: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Sealed {
  const ephemeral = x25519.generateKeypair();
  try {
    return sealWithEphemeral(suite, ephemeral.secretKey, recipientPublicKey, info, aad, plaintext);
  } finally {
    wipe(ephemeral.secretKey);
  }
}

/**
 * Decrypt.
 *
 * Throws if authentication fails — a corrupt, forged, or mis-addressed
 * ciphertext is indistinguishable here.
 */
export function open(
  suite: Suite,
  recipientSecretKey: Uint8Array,
  enc: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  if (enc.length !== ENC_BYTES) {
    throw new Error(`enc must be ${ENC_BYTES} bytes`);
  }
  if (ciphertext.length < TAG_BYTES) {
    throw new Error("ciphertext is shorter than the AEAD tag");
  }
  const dh = x25519.dh(recipientSecretKey, enc);
  const recipientPublicKey = x25519.publicKey(recipientSecretKey);
  const sharedSecret = extractAndExpand(dh, enc, recipientPublicKey);
  const context = keySchedule(suite, sharedSecret, info);
  try {
    return aead(suite, "decrypt", context.key, context.baseNonce, aad, ciphertext);
  } finally {
    wipe(dh, sharedSecret, context.key, context.baseNonce, context.exporterSecret);
  }
}

// ---------------------------------------------------------------- internals

/** The key schedule outputs of RFC 9180 §5.1. Exported for the vector tests. */
export type Context = { key: Uint8Array; baseNonce: Uint8Array; exporterSecret: Uint8Array };

/**
 * seal() with a caller-supplied ephemeral key. Exported for the RFC 9180
 * vectors, which pin skEm; outside a test a reused ephemeral key would repeat
 * the AEAD nonce.
 */
export function sealWithEphemeral(
  suite: Suite,
  ephemeralSecretKey: Uint8Array,
  recipientPublicKey: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Sealed {
  if (recipientPublicKey.length !== x25519.KEY_BYTES) {
    throw new Error(`recipient public key must be ${x25519.KEY_BYTES} bytes`);
  }
  const enc = x25519.publicKey(ephemeralSecretKey);
  const dh = x25519.dh(ephemeralSecretKey, recipientPublicKey);
  const sharedSecret = extractAndExpand(dh, enc, recipientPublicKey);
  const context = keySchedule(suite, sharedSecret, info);
  try {
    return { enc, ciphertext: aead(suite, "encrypt", context.key, context.baseNonce, aad, plaintext) };
  } finally {
    wipe(dh, sharedSecret, context.key, context.baseNonce, context.exporterSecret);
  }
}

/** DHKEM's ExtractAndExpand (RFC 9180 §4.1), shared by Encap and Decap. */
export function extractAndExpand(dh: Uint8Array, enc: Uint8Array, recipientPublicKey: Uint8Array): Uint8Array {
  const kemContext = concatBytes(enc, recipientPublicKey);
  const eaePrk = labeledExtract(KEM_SUITE_ID, EMPTY, "eae_prk", dh);
  try {
    return labeledExpand(KEM_SUITE_ID, eaePrk, "shared_secret", kemContext, NSECRET);
  } finally {
    wipe(eaePrk);
  }
}

/** KeySchedule for mode_base (RFC 9180 §5.1): psk and psk_id are empty. */
export function keySchedule(suite: Suite, sharedSecret: Uint8Array, info: Uint8Array): Context {
  const sid = suiteId(suite);
  const pskIdHash = labeledExtract(sid, EMPTY, "psk_id_hash", EMPTY);
  const infoHash = labeledExtract(sid, EMPTY, "info_hash", info);
  const keyScheduleContext = concatBytes(new Uint8Array([MODE_BASE]), pskIdHash, infoHash);

  const secret = labeledExtract(sid, sharedSecret, "secret", EMPTY);
  try {
    return {
      key: labeledExpand(sid, secret, "key", keyScheduleContext, keyBytes(suite)),
      baseNonce: labeledExpand(sid, secret, "base_nonce", keyScheduleContext, nonceBytes(suite)),
      exporterSecret: labeledExpand(sid, secret, "exp", keyScheduleContext, NH),
    };
  } finally {
    wipe(secret);
  }
}

function suiteId(suite: Suite): Uint8Array {
  return concatBytes(asciiToBytes("HPKE"), i2osp(KEM_ID, 2), i2osp(KDF_ID, 2), i2osp(aeadId(suite), 2));
}

function labeledExtract(sid: Uint8Array, salt: Uint8Array, label: string, ikm: Uint8Array): Uint8Array {
  return extract(salt, concatBytes(HPKE_V1, sid, asciiToBytes(label), ikm));
}

function labeledExpand(sid: Uint8Array, prk: Uint8Array, label: string, info: Uint8Array, length: number): Uint8Array {
  return expand(prk, concatBytes(i2osp(length, 2), HPKE_V1, sid, asciiToBytes(label), info), length);
}

/**
 * HKDF-Extract (RFC 5869 §2.2). An empty salt becomes HashLen zero bytes, as
 * the RFC specifies — HMAC zero-pads its key, so this is also what an
 * empty-key HMAC would produce, but spelling it out keeps it explicit.
 */
function extract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  return hmacSha256(salt.length === 0 ? new Uint8Array(NH) : salt, ikm);
}

/** HKDF-Expand (RFC 5869 §2.3). */
function expand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  if (length < 0 || length > 255 * NH) {
    throw new Error(`HKDF-Expand length out of range: ${length}`);
  }
  const out = new Uint8Array(length);
  let block: Uint8Array = EMPTY;
  let done = 0;
  for (let counter = 1; done < length; counter++) {
    block = hmacSha256(prk, concatBytes(block, info, new Uint8Array([counter])));
    const take = Math.min(block.length, length - done);
    out.set(block.subarray(0, take), done);
    done += take;
  }
  wipe(block);
  return out;
}

/**
 * One-shot AEAD at sequence number 0, where the nonce is the base nonce
 * unchanged (RFC 9180 §5.2 XORs the sequence number in; it is zero here).
 */
function aead(suite: Suite, mode: "encrypt" | "decrypt", key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, input: Uint8Array): Uint8Array {
  const cipher =
    suite === "X25519_SHA256_CHACHA20POLY1305" ? chacha20poly1305(key, nonce, aad) : gcm(key, nonce, aad);
  try {
    return mode === "encrypt" ? cipher.encrypt(input) : cipher.decrypt(input);
  } catch (e) {
    if (mode === "decrypt") {
      throw new Error(`HPKE open failed: ciphertext is not authentic (${(e as Error).message})`);
    }
    throw e;
  }
}

// ------------------------------------------------------------------ helpers

/** I2OSP(n, length): big-endian, fixed width. */
function i2osp(n: number, length: number): Uint8Array {
  return numberToBytesBE(BigInt(n), length);
}

function wipe(...secrets: Uint8Array[]): void {
  for (const secret of secrets) {
    secret.fill(0);
  }
}

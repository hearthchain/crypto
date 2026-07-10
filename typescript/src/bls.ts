// BLS12-381 key derivation per EIP-2333 (key generation) and EIP-2334 (paths) —
// the BLS analog of SLIP-0010. Only derivation is implemented: pure HKDF-SHA-256
// + SHA-256 + mod r, no pairing library.
//
// Unlike SLIP-0010, EIP-2333 has no hardened/non-hardened distinction: every
// child is derived from the parent secret key (hardened-equivalent), so paths
// carry no "'" marker.

import { bytesToNumberBE, concatBytes, numberToBytesBE } from "@noble/curves/utils.js";
import { hashSha256, hmacSha256 } from "./primitives.ts";

/** EIP-2334 purpose (the curve id). */
export const PURPOSE = 12381;

const LAMPORT_CHUNKS = 255;
const SHA256_LEN = 32;
const R = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;

/** Master secret key from a seed (>= 32 bytes). Returns a 32-byte big-endian scalar. */
export function deriveMasterSk(seed: Uint8Array): Uint8Array {
  if (seed.length < 32) {
    throw new Error("EIP-2333 seed must be at least 32 bytes");
  }
  return hkdfModR(seed, new Uint8Array(0));
}

/** One child derivation step. `index` is a uint32. */
export function deriveChildSk(parentSk: Uint8Array, index: number): Uint8Array {
  return hkdfModR(parentSkToLamportPk(parentSk, index), new Uint8Array(0));
}

/** Derive along an EIP-2334 path such as "m/12381/9381/0/0". */
export function derivePath(seed: Uint8Array, path: string): Uint8Array {
  let sk = deriveMasterSk(seed);
  for (const index of parsePath(path)) {
    sk = deriveChildSk(sk, index);
  }
  return sk;
}

export function parsePath(path: string): number[] {
  const t = path.trim();
  if (t !== "m" && !t.startsWith("m/")) {
    throw new Error(`path must start with 'm': ${path}`);
  }
  if (t === "m") {
    return [];
  }
  return t
    .slice(2)
    .split("/")
    .map((raw) => {
      if (raw.includes("'")) {
        throw new Error(`BLS (EIP-2333) has no hardened notation; drop the ' in '${raw}'`);
      }
      if (!/^\d+$/.test(raw) || Number(raw) > 0xffffffff) {
        throw new Error(`index out of uint32 range: ${raw}`);
      }
      return Number(raw);
    });
}

// --- EIP-2333 internals --------------------------------------------------

function hkdfModR(ikm: Uint8Array, keyInfo: Uint8Array): Uint8Array {
  const L = 48;
  let salt = utf8("BLS-SIG-KEYGEN-SALT-");
  let sk = 0n;
  while (sk === 0n) {
    salt = hashSha256(salt);
    const prk = hmacSha256(salt, concatBytes(ikm, Uint8Array.of(0))); // Extract(salt, IKM || I2OSP(0,1))
    const info = concatBytes(keyInfo, Uint8Array.of((L >> 8) & 0xff, L & 0xff));
    sk = bytesToNumberBE(hkdfExpand(prk, info, L)) % R;
  }
  return numberToBytesBE(sk, 32);
}

function parentSkToLamportPk(parentSk: Uint8Array, index: number): Uint8Array {
  const salt = new Uint8Array(4);
  new DataView(salt.buffer).setUint32(0, index >>> 0, false);
  const ikm = leftPad32(parentSk);
  const notIkm = ikm.map((b) => ~b & 0xff);
  const buf = new Uint8Array(2 * LAMPORT_CHUNKS * SHA256_LEN);
  let pos = 0;
  for (const chunk of ikmToLamportSk(salt, ikm)) {
    buf.set(hashSha256(chunk), pos);
    pos += SHA256_LEN;
  }
  for (const chunk of ikmToLamportSk(salt, notIkm)) {
    buf.set(hashSha256(chunk), pos);
    pos += SHA256_LEN;
  }
  return hashSha256(buf);
}

function ikmToLamportSk(salt: Uint8Array, ikm: Uint8Array): Uint8Array[] {
  const okm = hkdfExpand(hmacSha256(salt, ikm), new Uint8Array(0), LAMPORT_CHUNKS * SHA256_LEN);
  const chunks: Uint8Array[] = [];
  for (let i = 0; i < LAMPORT_CHUNKS; i++) {
    chunks.push(okm.slice(i * SHA256_LEN, (i + 1) * SHA256_LEN));
  }
  return chunks;
}

/** HKDF-Expand (RFC 5869) with HMAC-SHA-256. length must be <= 255*32. */
function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let t: Uint8Array = new Uint8Array(0);
  let pos = 0;
  let counter = 1;
  while (pos < length) {
    t = hmacSha256(prk, concatBytes(t, info, Uint8Array.of(counter & 0xff)));
    const n = Math.min(SHA256_LEN, length - pos);
    out.set(t.subarray(0, n), pos);
    pos += n;
    counter++;
  }
  return out;
}

function leftPad32(b: Uint8Array): Uint8Array {
  if (b.length >= 32) {
    return b;
  }
  const out = new Uint8Array(32);
  out.set(b, 32 - b.length);
  return out;
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

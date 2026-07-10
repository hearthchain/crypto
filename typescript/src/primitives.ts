// Low-level crypto primitives: hashing, HMAC, and the edwards25519 group/scalar
// arithmetic the VRF needs — all from the audited, zero-dependency @noble crates
// (the idiomatic pure-TypeScript choice; no libsodium/WASM).
//
// Note on "noclamp": libsodium's *_noclamp multiplies by the raw 256-bit scalar,
// whereas @noble scalars are reduced mod L. We reduce first; this is identical
// because every point we multiply here has order L (n*P == (n mod L)*P), so
// results match the other implementations byte-for-byte.

import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToNumberLE, numberToBytesLE } from "@noble/curves/utils.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";

const Point = ed25519.Point;

/** edwards25519 group order L. */
const L = 7237005577332262213973186563042994240857116359379907606001950938285454250989n;

function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function scalarFromLE(n: Uint8Array): bigint {
  return mod(bytesToNumberLE(n), L);
}

export const hashSha512 = (data: Uint8Array): Uint8Array => sha512(data);
export const hashSha256 = (data: Uint8Array): Uint8Array => sha256(data);
export const hmacSha512 = (key: Uint8Array, data: Uint8Array): Uint8Array => hmac(sha512, key, data);
export const hmacSha256 = (key: Uint8Array, data: Uint8Array): Uint8Array => hmac(sha256, key, data);

function decode(bytes: Uint8Array): InstanceType<typeof Point> | null {
  try {
    return Point.fromBytes(bytes);
  } catch {
    return null;
  }
}

/** Point addition on compressed points; null if either is off-curve. Only an
 * on-curve check (accepts non-prime-order points) — what RFC 9381
 * try-and-increment cofactor clearing needs. */
export function pointAdd(p: Uint8Array, q: Uint8Array): Uint8Array | null {
  const a = decode(p);
  const b = decode(q);
  return a && b ? a.add(b).toBytes() : null;
}

export function pointSub(p: Uint8Array, q: Uint8Array): Uint8Array | null {
  const a = decode(p);
  const b = decode(q);
  return a && b ? a.subtract(b).toBytes() : null;
}

/** n * p; null if p is off-curve. */
export function scalarmultNoclamp(n: Uint8Array, p: Uint8Array): Uint8Array | null {
  const pt = decode(p);
  return pt ? pt.multiplyUnsafe(scalarFromLE(n)).toBytes() : null;
}

/** n * B. */
export function scalarmultBaseNoclamp(n: Uint8Array): Uint8Array {
  return Point.BASE.multiplyUnsafe(scalarFromLE(n)).toBytes();
}

/** x * y mod L. */
export function scalarMul(x: Uint8Array, y: Uint8Array): Uint8Array {
  return numberToBytesLE(mod(scalarFromLE(x) * scalarFromLE(y), L), 32);
}

/** x + y mod L. */
export function scalarAdd(x: Uint8Array, y: Uint8Array): Uint8Array {
  return numberToBytesLE(mod(scalarFromLE(x) + scalarFromLE(y), L), 32);
}

/** Reduce a 64-byte little-endian value mod L to a 32-byte scalar. */
export function scalarReduce(wide: Uint8Array): Uint8Array {
  return numberToBytesLE(mod(bytesToNumberLE(wide), L), 32);
}

// Ed25519 (EdDSA, RFC 8032) keys and signatures — the standard, Ledger-native
// scheme. The same key material also backs the ECVRF (see ./ecvrf.ts).

import { ed25519 } from "@noble/curves/ed25519.js";
import { hashSha512 } from "./primitives.ts";

/** An Ed25519 keypair derived from a 32-byte seed. */
export class KeyPair {
  readonly seed: Uint8Array;
  readonly publicKey: Uint8Array;

  constructor(seed: Uint8Array, publicKey: Uint8Array) {
    this.seed = seed;
    this.publicKey = publicKey;
  }

  static fromSeed(seed: Uint8Array): KeyPair {
    if (seed.length !== 32) {
      throw new Error("Ed25519 seed must be 32 bytes");
    }
    return new KeyPair(seed, ed25519.getPublicKey(seed));
  }

  sign(message: Uint8Array): Uint8Array {
    return ed25519.sign(message, this.seed);
  }
}

export function verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

/** RFC 8032 secret scalar: clamp(SHA-512(seed)[0..32]). Used by ECVRF. */
export function secretScalar(seed: Uint8Array): Uint8Array {
  const a = hashSha512(seed).slice(0, 32);
  a[0] &= 0xf8;
  a[31] = (a[31] & 0x7f) | 0x40;
  return a;
}

/** RFC 8032 nonce prefix: SHA-512(seed)[32..64]. Used by ECVRF nonce gen. */
export function noncePrefix(seed: Uint8Array): Uint8Array {
  return hashSha512(seed).slice(32, 64);
}

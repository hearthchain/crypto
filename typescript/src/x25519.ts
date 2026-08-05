// X25519 (RFC 7748) over raw 32-byte little-endian keys — the Diffie-Hellman
// half of HPKE's DHKEM (./hpke.ts).
//
// Runs on @noble/curves (already a dependency for ed25519/ECVRF); @noble
// rejects a small-order public key internally (matching the RFC 9180 §7.1.4
// requirement that a KEM abort rather than derive from a degenerate DH
// output), and we re-check the output is non-zero as a defense-in-depth
// backstop so the contract holds regardless of the underlying implementation.

import { x25519 } from "@noble/curves/ed25519.js";
import { randomBytes } from "@noble/hashes/utils.js";

/** Size of both a private scalar and a public u-coordinate. */
export const KEY_BYTES = 32;

/** An X25519 keypair in raw little-endian form. */
export type Keypair = { publicKey: Uint8Array; secretKey: Uint8Array };

/** A fresh keypair. The secret is 32 uniformly random bytes; X25519 clamps
 * them when they are used, so every draw is a valid scalar. */
export function generateKeypair(): Keypair {
  const secretKey = randomBytes(KEY_BYTES);
  return { publicKey: publicKey(secretKey), secretKey };
}

/** The public key for a secret scalar, i.e. X25519(sk, 9). */
export function publicKey(secretKey: Uint8Array): Uint8Array {
  if (secretKey.length !== KEY_BYTES) {
    throw new Error(`X25519 secret key must be ${KEY_BYTES} bytes`);
  }
  return x25519.getPublicKey(secretKey);
}

/**
 * The Diffie-Hellman shared coordinate X25519(sk, pk).
 *
 * Throws if `publicKey` has small order (an all-zero result), which RFC 9180
 * §7.1.4 requires KEMs to reject.
 */
export function dh(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  if (secretKey.length !== KEY_BYTES) {
    throw new Error(`X25519 secret key must be ${KEY_BYTES} bytes`);
  }
  if (publicKey.length !== KEY_BYTES) {
    throw new Error(`X25519 public key must be ${KEY_BYTES} bytes`);
  }
  let shared: Uint8Array;
  try {
    shared = x25519.getSharedSecret(secretKey, publicKey);
  } catch (e) {
    throw new Error(`X25519 scalar multiplication failed: ${(e as Error).message}`);
  }
  if (shared.every((b) => b === 0)) {
    throw new Error("X25519: public key has small order");
  }
  return shared;
}

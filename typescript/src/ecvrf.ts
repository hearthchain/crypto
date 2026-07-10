// ECVRF-EDWARDS25519-SHA512-TAI, the RFC 9381 VRF (suite_string = 0x03). It
// reuses the exact Ed25519 key: the VRF secret scalar is clamp(SHA-512(seed))
// and the VRF public key is the Ed25519 public key.

import { concatBytes, equalBytes } from "@noble/curves/utils.js";
import { noncePrefix, secretScalar } from "./ed25519.ts";
import * as prim from "./primitives.ts";

const SUITE = 0x03;
const PROOF_LEN = 80; // 32 + 16 + 32
const IDENTITY = ((): Uint8Array => {
  const a = new Uint8Array(32);
  a[0] = 1;
  return a;
})();

/** A VRF proof pi = Gamma(32) || c(16) || s(32). */
export class Proof {
  readonly gamma: Uint8Array;
  readonly c: Uint8Array;
  readonly s: Uint8Array;

  constructor(gamma: Uint8Array, c: Uint8Array, s: Uint8Array) {
    this.gamma = gamma;
    this.c = c;
    this.s = s;
  }

  bytes(): Uint8Array {
    return concatBytes(this.gamma, this.c, this.s);
  }
}

/** Prove: returns the proof and the VRF output beta (64 bytes). */
export function prove(seed: Uint8Array, alpha: Uint8Array): { proof: Proof; beta: Uint8Array } {
  const x = secretScalar(seed);
  const y = prim.scalarmultBaseNoclamp(x); // public key Y = x*B
  const h = encodeToCurve(y, alpha);
  const gamma = must(prim.scalarmultNoclamp(x, h), "Gamma = x*H");
  const k = nonce(seed, h);
  const u = prim.scalarmultBaseNoclamp(k); // U = k*B
  const v = must(prim.scalarmultNoclamp(k, h), "V = k*H");
  const c = challenge(y, h, gamma, u, v); // 16 bytes
  const c32 = new Uint8Array(32);
  c32.set(c);
  const s = prim.scalarAdd(k, prim.scalarMul(c32, x)); // s = k + c*x mod L
  const proof = new Proof(gamma, c, s);
  return { proof, beta: proofToHash(proof) };
}

/** Verify a proof; the VRF output beta if valid, else null. */
export function verify(publicKey: Uint8Array, alpha: Uint8Array, pi: Uint8Array): Uint8Array | null {
  const proof = decode(pi);
  if (!proof) {
    return null;
  }
  const h = encodeToCurve(publicKey, alpha);
  const c32 = new Uint8Array(32);
  c32.set(proof.c);

  const sB = prim.scalarmultBaseNoclamp(proof.s);
  const cY = prim.scalarmultNoclamp(c32, publicKey);
  if (!cY) return null;
  const u = prim.pointSub(sB, cY); // U = s*B - c*Y
  if (!u) return null;
  const sH = prim.scalarmultNoclamp(proof.s, h);
  const cGamma = prim.scalarmultNoclamp(c32, proof.gamma);
  if (!sH || !cGamma) return null;
  const v = prim.pointSub(sH, cGamma); // V = s*H - c*Gamma
  if (!v) return null;

  return equalBytes(challenge(publicKey, h, proof.gamma, u, v), proof.c) ? proofToHash(proof) : null;
}

/** proof_to_hash: beta = SHA-512(suite || 0x03 || point_to_string(8*Gamma) || 0x00). */
export function proofToHash(proof: Proof): Uint8Array {
  const gamma8 = must(cofactorClear(proof.gamma), "8*Gamma");
  return prim.hashSha512(concatBytes(Uint8Array.of(SUITE, 0x03), gamma8, Uint8Array.of(0x00)));
}

export function decode(pi: Uint8Array): Proof | null {
  if (pi.length !== PROOF_LEN) {
    return null;
  }
  return new Proof(pi.slice(0, 32), pi.slice(32, 48), pi.slice(48, 80));
}

// --- internals -----------------------------------------------------------

/** ECVRF_encode_to_curve_try_and_increment (RFC 9381 §5.4.1.1). */
function encodeToCurve(pk: Uint8Array, alpha: Uint8Array): Uint8Array {
  for (let ctr = 0; ctr <= 255; ctr++) {
    const hash = prim.hashSha512(
      concatBytes(Uint8Array.of(SUITE, 0x01), pk, alpha, Uint8Array.of(ctr), Uint8Array.of(0x00)),
    );
    const cleared = cofactorClear(hash.slice(0, 32));
    if (cleared && !equalBytes(cleared, IDENTITY)) {
      return cleared;
    }
  }
  throw new Error("encode_to_curve: no valid point found");
}

/** Multiply a compressed point by cofactor 8 via three doublings (on-curve check only). */
function cofactorClear(p: Uint8Array): Uint8Array | null {
  const p2 = prim.pointAdd(p, p);
  if (!p2) return null;
  const p4 = prim.pointAdd(p2, p2);
  if (!p4) return null;
  return prim.pointAdd(p4, p4);
}

/** ECVRF_nonce_generation_RFC8032 (RFC 9381 §5.4.2.2). */
function nonce(seed: Uint8Array, h: Uint8Array): Uint8Array {
  return prim.scalarReduce(prim.hashSha512(concatBytes(noncePrefix(seed), h)));
}

/** ECVRF_challenge_generation (RFC 9381 §5.4.3): first 16 bytes. */
function challenge(y: Uint8Array, h: Uint8Array, gamma: Uint8Array, u: Uint8Array, v: Uint8Array): Uint8Array {
  return prim
    .hashSha512(concatBytes(Uint8Array.of(SUITE, 0x02), y, h, gamma, u, v, Uint8Array.of(0x00)))
    .slice(0, 16);
}

function must(v: Uint8Array | null, what: string): Uint8Array {
  if (!v) {
    throw new Error(`${what} failed`);
  }
  return v;
}

// The three role keys, derived from one BIP-39 seed at separate paths. Signing
// and VRF keys use different hardened SLIP-0010 role indices so their secret
// scalars are unrelated — removing the EdDSA/ECVRF shared-key risk. BLS finality
// keys live in their own EIP-2333 tree (different curve).

import * as bls from "./bls.ts";
import { KeyPair } from "./ed25519.ts";
import * as slip10 from "./slip10.ts";

const COIN_TYPE = 9381; // placeholder — register a SLIP-0044 value
const ROLE_SIGNING = 0;
const ROLE_VRF = 1;

export function signingPath(account = 0): string {
  return `m/44'/${COIN_TYPE}'/${account}'/${ROLE_SIGNING}'/0'`;
}

export function vrfPath(account = 0): string {
  return `m/44'/${COIN_TYPE}'/${account}'/${ROLE_VRF}'/0'`;
}

export function blsPath(account = 0): string {
  return `m/${bls.PURPOSE}/${COIN_TYPE}/${account}/0`;
}

/** ed25519 keypair for signing transactions. */
export function signingKey(seed: Uint8Array, account = 0): KeyPair {
  return KeyPair.fromSeed(slip10.derivePath(seed, signingPath(account)).privateKey);
}

/** ed25519 keypair for the VRF (its seed feeds ecvrf.prove; publicKey is the VRF key). */
export function vrfKey(seed: Uint8Array, account = 0): KeyPair {
  return KeyPair.fromSeed(slip10.derivePath(seed, vrfPath(account)).privateKey);
}

/** BLS12-381 finality secret key (32-byte big-endian scalar). */
export function blsSecretKey(seed: Uint8Array, account = 0): Uint8Array {
  return bls.derivePath(seed, blsPath(account));
}

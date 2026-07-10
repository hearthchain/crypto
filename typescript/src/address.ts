// Account addresses: Bech32m(hrp, versionByte || SHA-256(publicKey)[0:20]). The
// per-network HRP is a UX guard against sending to the wrong network; it is not
// replay protection (that belongs in the signed transaction).

import { concatBytes } from "@noble/curves/utils.js";
import * as bech32m from "./bech32m.ts";
import { hashSha256 } from "./primitives.ts";

/** Address network. */
export const Network = {
  Testnet: "testnet",
  Mainnet: "mainnet",
} as const;
export type Network = (typeof Network)[keyof typeof Network];

/** A decoded address. */
export interface Address {
  network: Network;
  hash: Uint8Array;
  version: number;
}

const ED25519_VERSION = 0x00;
const HASH_LEN = 20;

function hrpOf(network: Network): string {
  return network === Network.Mainnet ? "hrthm" : "hrtht";
}

function networkByHrp(hrp: string): Network | null {
  if (hrp === "hrthm") return Network.Mainnet;
  if (hrp === "hrtht") return Network.Testnet;
  return null;
}

/** Derive the address string for an Ed25519 public key on a given network. */
export function fromPublicKey(publicKey: Uint8Array, network: Network): string {
  if (publicKey.length !== 32) {
    throw new Error("public key must be 32 bytes");
  }
  const payload = concatBytes(Uint8Array.of(ED25519_VERSION), hashSha256(publicKey).slice(0, HASH_LEN));
  return bech32m.encode(hrpOf(network), payload);
}

/** Parse and validate an address string. */
export function parse(s: string): Address | null {
  const decoded = bech32m.decode(s);
  if (!decoded) {
    return null;
  }
  const [hrp, payload] = decoded;
  const network = networkByHrp(hrp);
  if (network === null || payload.length !== HASH_LEN + 1 || payload[0] !== ED25519_VERSION) {
    return null;
  }
  return { network, hash: payload.slice(1), version: payload[0] };
}

/** Parse and require a specific network (rejects cross-network addresses). */
export function parseFor(s: string, expected: Network): Address | null {
  const a = parse(s);
  return a && a.network === expected ? a : null;
}

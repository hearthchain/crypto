// SLIP-0010 hierarchical derivation for the ed25519 curve (hardened-only) — the
// derivation Ledger uses for Ed25519 accounts.

import { concatBytes } from "@noble/curves/utils.js";
import { hmacSha512 } from "./primitives.ts";

const HARDENED = 0x80000000;

/** A SLIP-0010 node. */
export interface Node {
  privateKey: Uint8Array;
  chainCode: Uint8Array;
}

/** Master node from a BIP-39 (or any) seed. */
export function master(seed: Uint8Array): Node {
  return split(hmacSha512(utf8("ed25519 seed"), seed));
}

/** One hardened child step (the hardened bit is added automatically). */
export function deriveChild(parent: Node, index: number): Node {
  const idx = new Uint8Array(4);
  new DataView(idx.buffer).setUint32(0, index + HARDENED, false);
  return split(hmacSha512(parent.chainCode, concatBytes(Uint8Array.of(0), parent.privateKey, idx)));
}

/** Derive along a path such as "m/44'/9381'/0'/0'/0'". Every level is hardened. */
export function derivePath(seed: Uint8Array, path: string): Node {
  let node = master(seed);
  for (const index of parsePath(path)) {
    node = deriveChild(node, index);
  }
  return node;
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
      const cleaned = raw.replace(/['hH]+$/, "");
      if (!/^\d+$/.test(cleaned)) {
        throw new Error(`bad path segment: '${raw}'`);
      }
      const n = Number(cleaned);
      if (n >= HARDENED) {
        throw new Error(`index out of range: ${raw}`);
      }
      return n;
    });
}

function split(i: Uint8Array): Node {
  return { privateKey: i.slice(0, 32), chainCode: i.slice(32, 64) };
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

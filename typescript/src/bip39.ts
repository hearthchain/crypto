// BIP-39 mnemonic validation and seed derivation. The seed derivation
// (PBKDF2-HMAC-SHA512, 2048 iterations) uses @noble/hashes; NFKD normalization
// uses the built-in String.prototype.normalize.

import { readFileSync } from "node:fs";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { hashSha256 } from "./primitives.ts";

const WORDLIST_RAW = readFileSync(new URL("./english.txt", import.meta.url), "utf8");
const WORDLIST = WORDLIST_RAW.split(/\s+/).filter((w) => w.length > 0);
const WORD_INDEX = new Map(WORDLIST.map((w, i): [string, number] => [w, i]));

/** The outcome of validate(): valid, or invalid with a reason. */
export type ValidationResult = { valid: true } | { valid: false; reason: string };

const normalize = (s: string): string => s.normalize("NFKD");
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/** Validate the BIP-39 checksum. */
export function validate(mnemonic: string): ValidationResult {
  const words = normalize(mnemonic).split(/\s+/).filter((w) => w.length > 0);
  const n = words.length;
  if (![12, 15, 18, 21, 24].includes(n)) {
    return { valid: false, reason: `word count must be 12/15/18/21/24, got ${n}` };
  }
  const indices: number[] = [];
  for (const w of words) {
    const idx = WORD_INDEX.get(w);
    if (idx === undefined) {
      return { valid: false, reason: `unknown word: '${w}'` };
    }
    indices.push(idx);
  }

  const totalBits = n * 11;
  const checksumBits = totalBits / 33;
  const entropyBits = totalBits - checksumBits;
  const bits: number[] = [];
  for (const idx of indices) {
    for (let b = 10; b >= 0; b--) {
      bits.push((idx >> b) & 1);
    }
  }
  const hash = hashSha256(bitsToBytes(bits.slice(0, entropyBits)));
  for (let i = 0; i < checksumBits; i++) {
    const expected = (hash[i >> 3] >> (7 - (i & 7))) & 1;
    if (bits[entropyBits + i] !== expected) {
      return { valid: false, reason: "checksum mismatch" };
    }
  }
  return { valid: true };
}

/** Derive the 64-byte BIP-39 seed from a mnemonic and optional passphrase. */
export function toSeed(mnemonic: string, passphrase = ""): Uint8Array {
  const password = utf8(normalize(mnemonic));
  const salt = utf8(normalize("mnemonic" + passphrase));
  return pbkdf2(sha512, password, salt, { c: 2048, dkLen: 64 });
}

/** The raw embedded wordlist text (for the checksum-drift guard). */
export const wordlistRaw = (): string => WORDLIST_RAW;

function bitsToBytes(bits: number[]): Uint8Array {
  const out = new Uint8Array(bits.length / 8);
  for (let i = 0; i < bits.length; i += 8) {
    let b = 0;
    for (let j = 0; j < 8; j++) {
      b = (b << 1) | bits[i + j];
    }
    out[i >> 3] = b;
  }
  return out;
}

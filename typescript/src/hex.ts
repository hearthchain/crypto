import { bytesToHex, hexToBytes } from "@noble/curves/utils.js";

export const encode = (bytes: Uint8Array): string => bytesToHex(bytes);

export const decode = (s: string): Uint8Array => hexToBytes(s.replace(/\s+/g, ""));

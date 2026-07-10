// Bech32m encoder/decoder (BIP-350), checksum constant 0x2bc830a3.

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const CONST = 0x2bc830a3;
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

export function encode(hrp: string, data: Uint8Array): string {
  const values = convertBits(Array.from(data), 8, 5, true);
  if (values === null) {
    throw new Error("cannot regroup payload bits");
  }
  const combined = values.concat(createChecksum(hrp, values));
  return hrp + "1" + combined.map((v) => CHARSET[v]).join("");
}

/** Verify structure + checksum only; returns [hrp, raw 5-bit groups] or null. */
export function decodeRaw(s: string): [string, number[]] | null {
  if (s !== s.toLowerCase() && s !== s.toUpperCase()) {
    return null;
  }
  const lower = s.toLowerCase();
  const pos = lower.lastIndexOf("1");
  if (pos < 1 || lower.length - pos - 1 < 6) {
    return null;
  }
  const hrp = lower.slice(0, pos);
  const dataPart = lower.slice(pos + 1);
  const values: number[] = [];
  for (const ch of dataPart) {
    const idx = CHARSET.indexOf(ch);
    if (idx < 0) {
      return null;
    }
    values.push(idx);
  }
  if (polymod(hrpExpand(hrp).concat(values)) !== CONST) {
    return null;
  }
  return [hrp, values.slice(0, values.length - 6)];
}

/** Decode into [hrp, payload bytes] — the byte-aligned form addresses use. */
export function decode(s: string): [string, Uint8Array] | null {
  const raw = decodeRaw(s);
  if (!raw) {
    return null;
  }
  const bytes = convertBits(raw[1], 5, 8, false);
  return bytes === null ? null : [raw[0], Uint8Array.from(bytes)];
}

// --- internals -----------------------------------------------------------

function polymod(values: number[]): number {
  let chk = 1;
  for (const v of values) {
    const b = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((b >> i) & 1) {
        chk ^= GEN[i];
      }
    }
  }
  return chk >>> 0;
}

function hrpExpand(hrp: string): number[] {
  const out: number[] = [];
  for (const c of hrp) out.push(c.charCodeAt(0) >> 5);
  out.push(0);
  for (const c of hrp) out.push(c.charCodeAt(0) & 31);
  return out;
}

function createChecksum(hrp: string, data: number[]): number[] {
  const values = hrpExpand(hrp).concat(data, [0, 0, 0, 0, 0, 0]);
  const pm = polymod(values) ^ CONST;
  const out: number[] = [];
  for (let i = 0; i < 6; i++) {
    out.push((pm >> (5 * (5 - i))) & 31);
  }
  return out;
}

/** Regroup a bit stream; null on failure. */
function convertBits(data: number[], from: number, to: number, pad: boolean): number[] | null {
  let acc = 0;
  let bits = 0;
  const maxv = (1 << to) - 1;
  const out: number[] = [];
  for (const value of data) {
    if (value < 0 || value >> from !== 0) {
      return null;
    }
    acc = (acc << from) | value;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) {
      out.push((acc << (to - bits)) & maxv);
    }
  } else if (bits >= from || ((acc << (to - bits)) & maxv) !== 0) {
    return null;
  }
  return out;
}

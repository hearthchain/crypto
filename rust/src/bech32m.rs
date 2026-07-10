//! Bech32m encoder/decoder (BIP-350), checksum constant 0x2bc830a3.

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const CONST: u32 = 0x2bc8_30a3;
const GEN: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

pub fn encode(hrp: &str, data: &[u8]) -> String {
    let mut values = convert_bits(
        &data.iter().map(|&b| b as u32).collect::<Vec<_>>(),
        8,
        5,
        true,
    )
    .expect("regroup");
    let checksum = create_checksum(hrp, &values);
    values.extend_from_slice(&checksum);
    let mut s = String::with_capacity(hrp.len() + 1 + values.len());
    s.push_str(hrp);
    s.push('1');
    for v in &values {
        s.push(CHARSET[*v as usize] as char);
    }
    s
}

/// Verify structure + checksum only; returns (hrp, raw 5-bit groups).
pub fn decode_raw(s: &str) -> Option<(String, Vec<u32>)> {
    if s != s.to_lowercase() && s != s.to_uppercase() {
        return None;
    }
    let lower = s.to_lowercase();
    let pos = lower.rfind('1')?;
    if pos < 1 || lower.len() - pos - 1 < 6 {
        return None;
    }
    let hrp = &lower[..pos];
    let data_part = &lower[pos + 1..];
    let mut values = Vec::with_capacity(data_part.len());
    for ch in data_part.bytes() {
        let idx = CHARSET.iter().position(|&c| c == ch)?;
        values.push(idx as u32);
    }
    let mut check = hrp_expand(hrp);
    check.extend_from_slice(&values);
    if polymod(&check) != CONST {
        return None;
    }
    values.truncate(values.len() - 6);
    Some((hrp.to_string(), values))
}

/// Decode into (hrp, payload bytes) — the byte-aligned form addresses use.
pub fn decode(s: &str) -> Option<(String, Vec<u8>)> {
    let (hrp, values) = decode_raw(s)?;
    let bytes = convert_bits(&values, 5, 8, false)?;
    Some((hrp, bytes.into_iter().map(|v| v as u8).collect()))
}

// --- internals -----------------------------------------------------------

fn polymod(values: &[u32]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ v;
        for (i, &g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u32> {
    let mut out = Vec::with_capacity(hrp.len() * 2 + 1);
    for b in hrp.bytes() {
        out.push((b >> 5) as u32);
    }
    out.push(0);
    for b in hrp.bytes() {
        out.push((b & 31) as u32);
    }
    out
}

fn create_checksum(hrp: &str, data: &[u32]) -> Vec<u32> {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    let pm = polymod(&values) ^ CONST;
    (0..6).map(|i| (pm >> (5 * (5 - i))) & 31).collect()
}

/// Regroup a bit stream; `None` on failure.
fn convert_bits(data: &[u32], from: u32, to: u32, pad: bool) -> Option<Vec<u32>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let maxv: u32 = (1 << to) - 1;
    let mut out = Vec::new();
    for &value in data {
        if (value >> from) != 0 {
            return None;
        }
        acc = (acc << from) | value;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push((acc >> bits) & maxv);
        }
    }
    if pad {
        if bits > 0 {
            out.push((acc << (to - bits)) & maxv);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return None;
    }
    Some(out)
}

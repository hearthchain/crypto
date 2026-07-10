package tech.hearth.crypto;

import java.util.Optional;

/**
 * Bech32m encoder/decoder (BIP-350) — the modern human-readable address format
 * with strong error detection. Checksum constant 0x2bc830a3 (not original
 * Bech32's 1).
 */
public final class Bech32m {
    private Bech32m() {}

    private static final String CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private static final int CONST = 0x2bc830a3;
    private static final int[] GEN = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};

    /** Structure + checksum only, with the raw 5-bit data groups (checksum stripped). */
    public record DecodedRaw(String hrp, int[] values) {}

    /** hrp + byte-aligned payload. */
    public record Decoded(String hrp, byte[] data) {}

    public static String encode(String hrp, byte[] data) {
        int[] values = convertBits(bytesToInts(data), 8, 5, true);
        if (values == null) {
            throw new IllegalArgumentException("cannot regroup payload bits");
        }
        int[] checksum = createChecksum(hrp, values);
        StringBuilder sb = new StringBuilder(hrp).append('1');
        for (int v : values) {
            sb.append(CHARSET.charAt(v));
        }
        for (int v : checksum) {
            sb.append(CHARSET.charAt(v));
        }
        return sb.toString();
    }

    /** Verify structure + checksum. Present with the raw 5-bit data on success. */
    public static Optional<DecodedRaw> decodeRaw(String s) {
        if (!s.equals(s.toLowerCase()) && !s.equals(s.toUpperCase())) {
            return Optional.empty();
        }
        String lower = s.toLowerCase();
        int pos = lower.lastIndexOf('1');
        if (pos < 1 || lower.length() - pos - 1 < 6) {
            return Optional.empty();
        }
        String hrp = lower.substring(0, pos);
        String dataPart = lower.substring(pos + 1);
        int[] values = new int[dataPart.length()];
        for (int i = 0; i < dataPart.length(); i++) {
            int idx = CHARSET.indexOf(dataPart.charAt(i));
            if (idx < 0) {
                return Optional.empty();
            }
            values[i] = idx;
        }
        if (polymod(concat(hrpExpand(hrp), values)) != CONST) {
            return Optional.empty();
        }
        int[] data = new int[values.length - 6];
        System.arraycopy(values, 0, data, 0, data.length);
        return Optional.of(new DecodedRaw(hrp, data));
    }

    /** Decode into (hrp, payload bytes) — the byte-aligned form addresses use. */
    public static Optional<Decoded> decode(String s) {
        return decodeRaw(s).flatMap(raw -> {
            int[] bits = convertBits(raw.values(), 5, 8, false);
            if (bits == null) {
                return Optional.empty();
            }
            return Optional.of(new Decoded(raw.hrp(), intsToBytes(bits)));
        });
    }

    // --- internals -----------------------------------------------------------

    private static int polymod(int[] values) {
        int chk = 1;
        for (int v : values) {
            int b = chk >>> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ v;
            for (int i = 0; i < 5; i++) {
                if (((b >> i) & 1) == 1) {
                    chk ^= GEN[i];
                }
            }
        }
        return chk;
    }

    private static int[] hrpExpand(String hrp) {
        int[] out = new int[hrp.length() * 2 + 1];
        for (int i = 0; i < hrp.length(); i++) {
            out[i] = hrp.charAt(i) >> 5;
            out[hrp.length() + 1 + i] = hrp.charAt(i) & 31;
        }
        out[hrp.length()] = 0;
        return out;
    }

    private static int[] createChecksum(String hrp, int[] data) {
        int[] values = concat(concat(hrpExpand(hrp), data), new int[6]);
        int pm = polymod(values) ^ CONST;
        int[] out = new int[6];
        for (int i = 0; i < 6; i++) {
            out[i] = (pm >> (5 * (5 - i))) & 31;
        }
        return out;
    }

    /** Regroup a bit stream; returns null on failure (valid empty result is a non-null empty array). */
    private static int[] convertBits(int[] data, int from, int to, boolean pad) {
        int acc = 0;
        int bits = 0;
        int maxv = (1 << to) - 1;
        int[] out = new int[0];
        int outLen = 0;
        for (int value : data) {
            if (value < 0 || (value >> from) != 0) {
                return null;
            }
            acc = (acc << from) | value;
            bits += from;
            while (bits >= to) {
                bits -= to;
                out = ensureCapacity(out, outLen + 1);
                out[outLen++] = (acc >> bits) & maxv;
            }
        }
        if (pad) {
            if (bits > 0) {
                out = ensureCapacity(out, outLen + 1);
                out[outLen++] = (acc << (to - bits)) & maxv;
            }
        } else if (bits >= from || ((acc << (to - bits)) & maxv) != 0) {
            return null;
        }
        int[] trimmed = new int[outLen];
        System.arraycopy(out, 0, trimmed, 0, outLen);
        return trimmed;
    }

    private static int[] ensureCapacity(int[] arr, int min) {
        if (arr.length >= min) {
            return arr;
        }
        int[] bigger = new int[Math.max(min, arr.length * 2 + 1)];
        System.arraycopy(arr, 0, bigger, 0, arr.length);
        return bigger;
    }

    private static int[] concat(int[] a, int[] b) {
        int[] out = new int[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static int[] bytesToInts(byte[] b) {
        int[] out = new int[b.length];
        for (int i = 0; i < b.length; i++) {
            out[i] = b[i] & 0xff;
        }
        return out;
    }

    private static byte[] intsToBytes(int[] vals) {
        byte[] out = new byte[vals.length];
        for (int i = 0; i < vals.length; i++) {
            out[i] = (byte) vals[i];
        }
        return out;
    }
}

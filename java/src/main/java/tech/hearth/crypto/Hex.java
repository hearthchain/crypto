package tech.hearth.crypto;

/** Hex helpers. */
public final class Hex {
    private Hex() {}

    private static final char[] HEXCHARS = "0123456789abcdef".toCharArray();

    public static String encode(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xff;
            out[i * 2] = HEXCHARS[v >>> 4];
            out[i * 2 + 1] = HEXCHARS[v & 0x0f];
        }
        return new String(out);
    }

    public static byte[] decode(String s) {
        String clean = s.trim().replaceAll("\\s", "");
        if (clean.length() % 2 != 0) {
            throw new IllegalArgumentException("hex string must have even length");
        }
        byte[] out = new byte[clean.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}

package tech.hearth.crypto;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * BLS12-381 key derivation per EIP-2333 (key generation) and EIP-2334 (paths) —
 * the BLS analog of SLIP-0010. Only derivation is implemented: pure HKDF-SHA-256
 * + SHA-256 + mod r, no pairing library.
 *
 * <p>Unlike SLIP-0010, EIP-2333 has no hardened/non-hardened distinction: every
 * child is derived from the parent secret key (hardened-equivalent), and paths
 * carry no {@code '} marker.
 */
public final class Bls {
    private Bls() {}

    /** BLS12-381 subgroup order r. */
    public static final BigInteger R =
            new BigInteger("52435875175126190479447740508185965837690552500527637822603658699938581184513");

    /** EIP-2334 purpose (the curve id). */
    public static final long PURPOSE = 12381L;

    private static final byte[] KEYGEN_SALT = "BLS-SIG-KEYGEN-SALT-".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final int SHA256_LEN = 32;
    private static final int LAMPORT_CHUNKS = 255;

    /** Master secret key using the default backend. */
    public static byte[] deriveMasterSK(byte[] seed) {
        return deriveMasterSK(seed, Crypto.defaultBackend());
    }

    /** One child derivation step using the default backend. */
    public static byte[] deriveChildSK(byte[] parentSK, long index) {
        return deriveChildSK(parentSK, index, Crypto.defaultBackend());
    }

    /** Derive along an EIP-2334 path using the default backend. */
    public static byte[] derivePath(byte[] seed, String path) {
        return derivePath(seed, path, Crypto.defaultBackend());
    }

    /** Master secret key from a seed (>= 32 bytes). Returns a 32-byte big-endian scalar. */
    public static byte[] deriveMasterSK(byte[] seed, CryptoBackend backend) {
        if (seed.length < 32) {
            throw new IllegalArgumentException("EIP-2333 seed must be at least 32 bytes");
        }
        return hkdfModR(seed, new byte[0], backend);
    }

    /** One child derivation step. {@code index} is a uint32 (0 .. 2^32-1). */
    public static byte[] deriveChildSK(byte[] parentSK, long index, CryptoBackend backend) {
        if (index < 0 || index > 0xFFFFFFFFL) {
            throw new IllegalArgumentException("index must fit in uint32");
        }
        return hkdfModR(parentSKToLamportPK(parentSK, index, backend), new byte[0], backend);
    }

    /** Derive along an EIP-2334 path such as "m/12381/9381/0/0". */
    public static byte[] derivePath(byte[] seed, String path, CryptoBackend backend) {
        byte[] sk = deriveMasterSK(seed, backend);
        for (long idx : parsePath(path)) {
            sk = deriveChildSK(sk, idx, backend);
        }
        return sk;
    }

    public static long[] parsePath(String path) {
        String trimmed = path.trim();
        if (!trimmed.equals("m") && !trimmed.startsWith("m/")) {
            throw new IllegalArgumentException("path must start with 'm': " + path);
        }
        if (trimmed.equals("m")) {
            return new long[0];
        }
        String[] parts = trimmed.substring(2).split("/");
        long[] out = new long[parts.length];
        for (int i = 0; i < parts.length; i++) {
            String raw = parts[i];
            if (raw.contains("'")) {
                throw new IllegalArgumentException(
                        "BLS (EIP-2333) has no hardened notation; drop the ' in '" + raw + "'");
            }
            long n;
            try {
                n = Long.parseLong(raw);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("index out of uint32 range: " + raw);
            }
            if (n < 0 || n > 0xFFFFFFFFL) {
                throw new IllegalArgumentException("index out of uint32 range: " + raw);
            }
            out[i] = n;
        }
        return out;
    }

    // --- EIP-2333 internals --------------------------------------------------

    private static byte[] hkdfModR(byte[] ikm, byte[] keyInfo, CryptoBackend backend) {
        final int l = 48; // ceil((3 * ceil(log2(r))) / 16)
        byte[] salt = KEYGEN_SALT;
        BigInteger sk = BigInteger.ZERO;
        while (sk.signum() == 0) {
            salt = backend.sha256(salt);
            byte[] prk = backend.hmacSha256(salt, concat(ikm, new byte[]{0x00})); // Extract(salt, IKM || I2OSP(0,1))
            byte[] info = concat(keyInfo, new byte[]{(byte) (l >>> 8), (byte) l});
            byte[] okm = hkdfExpand(prk, info, l, backend);
            sk = os2ip(okm).mod(R);
        }
        return i2osp(sk, 32);
    }

    private static byte[] parentSKToLamportPK(byte[] parentSK, long index, CryptoBackend backend) {
        byte[] salt = {(byte) (index >>> 24), (byte) (index >>> 16), (byte) (index >>> 8), (byte) index};
        byte[] ikm = leftPad(parentSK, 32);
        byte[] notIkm = new byte[ikm.length];
        for (int i = 0; i < ikm.length; i++) {
            notIkm[i] = (byte) ~ikm[i];
        }
        byte[] buf = new byte[2 * LAMPORT_CHUNKS * SHA256_LEN];
        byte[][] lamport0 = ikmToLamportSK(salt, ikm, backend);
        byte[][] lamport1 = ikmToLamportSK(salt, notIkm, backend);
        int pos = 0;
        for (byte[] chunk : lamport0) {
            System.arraycopy(backend.sha256(chunk), 0, buf, pos, SHA256_LEN);
            pos += SHA256_LEN;
        }
        for (byte[] chunk : lamport1) {
            System.arraycopy(backend.sha256(chunk), 0, buf, pos, SHA256_LEN);
            pos += SHA256_LEN;
        }
        return backend.sha256(buf);
    }

    private static byte[][] ikmToLamportSK(byte[] salt, byte[] ikm, CryptoBackend backend) {
        byte[] okm = hkdfExpand(backend.hmacSha256(salt, ikm), new byte[0], LAMPORT_CHUNKS * SHA256_LEN, backend);
        byte[][] chunks = new byte[LAMPORT_CHUNKS][];
        for (int i = 0; i < LAMPORT_CHUNKS; i++) {
            chunks[i] = Arrays.copyOfRange(okm, i * SHA256_LEN, (i + 1) * SHA256_LEN);
        }
        return chunks;
    }

    /** HKDF-Expand (RFC 5869) with HMAC-SHA-256. {@code length} must be <= 255*32. */
    private static byte[] hkdfExpand(byte[] prk, byte[] info, int length, CryptoBackend backend) {
        byte[] out = new byte[length];
        byte[] t = new byte[0];
        int pos = 0;
        int counter = 1;
        while (pos < length) {
            t = backend.hmacSha256(prk, concat(t, info, new byte[]{(byte) counter}));
            int n = Math.min(SHA256_LEN, length - pos);
            System.arraycopy(t, 0, out, pos, n);
            pos += n;
            counter++;
        }
        return out;
    }

    // --- primitives ----------------------------------------------------------

    private static byte[] i2osp(BigInteger value, int len) {
        byte[] be = value.toByteArray();
        // strip a leading sign byte if present
        if (be.length > 1 && be[0] == 0) {
            be = Arrays.copyOfRange(be, 1, be.length);
        }
        if (be.length > len) {
            throw new IllegalArgumentException("value too large for I2OSP length");
        }
        byte[] out = new byte[len];
        System.arraycopy(be, 0, out, len - be.length, be.length);
        return out;
    }

    private static BigInteger os2ip(byte[] bytes) {
        return new BigInteger(1, bytes);
    }

    private static byte[] leftPad(byte[] b, int length) {
        if (b.length >= length) {
            return b;
        }
        byte[] out = new byte[length];
        System.arraycopy(b, 0, out, length - b.length, b.length);
        return out;
    }

    private static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int pos = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, pos, p.length);
            pos += p.length;
        }
        return out;
    }
}

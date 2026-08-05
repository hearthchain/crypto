package tech.hearth.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Optional;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import tech.hearth.crypto.Ed25519Math.Point;

/**
 * Pure-JVM implementation of {@link CryptoBackend}: JDK digests/HMAC plus the
 * BigInteger edwards25519 arithmetic in {@link Ed25519Math}. Produces byte-for-byte
 * the same Ed25519 signatures (RFC 8032) and ECVRF proofs (RFC 9381) as the
 * libsodium backend, so it is a drop-in fallback. Not constant-time.
 */
public final class JvmBackend implements CryptoBackend {

    public static final JvmBackend INSTANCE = new JvmBackend();

    private JvmBackend() {}

    @Override
    public String name() {
        return "jvm";
    }

    @Override
    public byte[] sha512(byte[] in) {
        return digest("SHA-512", in);
    }

    @Override
    public byte[] sha256(byte[] in) {
        return digest("SHA-256", in);
    }

    private static byte[] digest(String algorithm, byte[] in) {
        try {
            return MessageDigest.getInstance(algorithm).digest(in);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public byte[] hmacSha512(byte[] key, byte[] msg) {
        return hmac("HmacSHA512", key, msg);
    }

    @Override
    public byte[] hmacSha256(byte[] key, byte[] msg) {
        return hmac("HmacSHA256", key, msg);
    }

    private static byte[] hmac(String algorithm, byte[] key, byte[] msg) {
        try {
            Mac mac = Mac.getInstance(algorithm);
            // Empty HMAC keys are legal but SecretKeySpec rejects them; pad to a zero byte.
            byte[] k = key.length == 0 ? new byte[1] : key;
            mac.init(new SecretKeySpec(k, algorithm));
            return mac.doFinal(msg);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public RawKeypair signSeedKeypair(byte[] seed) {
        if (seed.length != 32) {
            throw new IllegalArgumentException("seed must be 32 bytes");
        }
        BigInteger a = Ed25519Math.scalarFromLE(clamp(sliceHash(sha512(seed))));
        byte[] pk = Ed25519Math.encode(Ed25519Math.mulBase(a));
        return new RawKeypair(pk, concat(seed, pk));
    }

    @Override
    public byte[] signDetached(byte[] msg, byte[] secretKey) {
        if (secretKey.length != 64) {
            throw new IllegalArgumentException("secret key must be 64 bytes");
        }
        byte[] seed = java.util.Arrays.copyOfRange(secretKey, 0, 32);
        byte[] pub = java.util.Arrays.copyOfRange(secretKey, 32, 64);
        byte[] h = sha512(seed);
        BigInteger a = Ed25519Math.scalarFromLE(clamp(sliceHash(h)));
        byte[] prefix = java.util.Arrays.copyOfRange(h, 32, 64);
        BigInteger r = Ed25519Math.scalarFromLE(sha512(concat(prefix, msg))).mod(Ed25519Math.L);
        byte[] rB = Ed25519Math.encode(Ed25519Math.mulBase(r));
        BigInteger k = Ed25519Math.scalarFromLE(sha512(concat(rB, pub, msg))).mod(Ed25519Math.L);
        BigInteger s = r.add(k.multiply(a)).mod(Ed25519Math.L);
        return concat(rB, Ed25519Math.scalarToLE32(s));
    }

    @Override
    public boolean verifyDetached(byte[] sig, byte[] msg, byte[] publicKey) {
        if (sig.length != 64 || publicKey.length != 32) {
            return false;
        }
        byte[] rBytes = java.util.Arrays.copyOfRange(sig, 0, 32);
        BigInteger s = Ed25519Math.scalarFromLE(java.util.Arrays.copyOfRange(sig, 32, 64));
        if (s.compareTo(Ed25519Math.L) >= 0) {
            return false;
        }
        Point aPt = Ed25519Math.decode(publicKey);
        Point rPt = Ed25519Math.decode(rBytes);
        if (aPt == null || rPt == null) {
            return false;
        }
        // Reject a small-order A or R: otherwise [k]A (or the R term) takes too
        // few distinct values, letting an attacker forge a signature for a
        // chosen message without knowing any private key — see
        // Ed25519Math.isSmallOrder.
        if (Ed25519Math.isSmallOrder(aPt) || Ed25519Math.isSmallOrder(rPt)) {
            return false;
        }
        BigInteger k = Ed25519Math.scalarFromLE(sha512(concat(rBytes, publicKey, msg))).mod(Ed25519Math.L);
        Point lhs = Ed25519Math.mulBase(s);                 // [S]B
        Point rhs = Ed25519Math.add(rPt, Ed25519Math.mul(k, aPt)); // R + [k]A
        return lhs.x().equals(rhs.x()) && lhs.y().equals(rhs.y());
    }

    @Override
    public Optional<byte[]> pointAdd(byte[] p, byte[] q) {
        Point a = Ed25519Math.decode(p);
        Point b = Ed25519Math.decode(q);
        if (a == null || b == null) {
            return Optional.empty();
        }
        return Optional.of(Ed25519Math.encode(Ed25519Math.add(a, b)));
    }

    @Override
    public Optional<byte[]> pointSub(byte[] p, byte[] q) {
        Point a = Ed25519Math.decode(p);
        Point b = Ed25519Math.decode(q);
        if (a == null || b == null) {
            return Optional.empty();
        }
        return Optional.of(Ed25519Math.encode(Ed25519Math.add(a, Ed25519Math.negate(b))));
    }

    @Override
    public Optional<byte[]> scalarmultNoclamp(byte[] n, byte[] p) {
        BigInteger scalar = Ed25519Math.scalarFromLE(n);
        Point pt = Ed25519Math.decode(p);
        if (pt == null || scalar.signum() == 0 || !Ed25519Math.isOnMainSubgroup(pt)) {
            return Optional.empty();
        }
        Point q = Ed25519Math.mul(scalar, pt);
        // libsodium rejects an infinity result.
        return Ed25519Math.isIdentity(q) ? Optional.empty() : Optional.of(Ed25519Math.encode(q));
    }

    @Override
    public byte[] scalarmultBaseNoclamp(byte[] n) {
        return Ed25519Math.encode(Ed25519Math.mulBase(Ed25519Math.scalarFromLE(n)));
    }

    @Override
    public byte[] scalarMul(byte[] x, byte[] y) {
        return Ed25519Math.scalarToLE32(
                Ed25519Math.scalarFromLE(x).multiply(Ed25519Math.scalarFromLE(y)).mod(Ed25519Math.L));
    }

    @Override
    public byte[] scalarAdd(byte[] x, byte[] y) {
        return Ed25519Math.scalarToLE32(
                Ed25519Math.scalarFromLE(x).add(Ed25519Math.scalarFromLE(y)).mod(Ed25519Math.L));
    }

    @Override
    public byte[] scalarReduce(byte[] wide) {
        if (wide.length != 64) {
            throw new IllegalArgumentException("input must be 64 bytes");
        }
        return Ed25519Math.scalarToLE32(Ed25519Math.scalarFromLE(wide).mod(Ed25519Math.L));
    }

    private static byte[] clamp(byte[] a) {
        byte[] c = a.clone();
        c[0] = (byte) (c[0] & 0xf8);
        c[31] = (byte) ((c[31] & 0x7f) | 0x40);
        return c;
    }

    private static byte[] sliceHash(byte[] h) {
        return java.util.Arrays.copyOfRange(h, 0, 32);
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

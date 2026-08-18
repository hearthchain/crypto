package tech.hearth.crypto;

import java.math.BigInteger;

/**
 * Self-contained edwards25519 field/group arithmetic (RFC 8032 / RFC 7748) in
 * {@link BigInteger}. Correctness-first, not constant-time — it exists purely as
 * the pure-JVM fallback for {@link JvmBackend} when native libsodium is absent.
 *
 * <p>Points are affine (x, y) mod p; encoding is the 32-byte little-endian
 * RFC 8032 compressed form. Addition uses the complete twisted-Edwards formula
 * (a = -1).
 */
final class Ed25519Math {
    private Ed25519Math() {}

    private static final BigInteger TWO = BigInteger.valueOf(2);
    static final BigInteger P = TWO.pow(255).subtract(BigInteger.valueOf(19));
    /** Group order L. */
    static final BigInteger L = TWO.pow(252).add(new BigInteger("27742317777372353535851937790883648493"));
    private static final BigInteger D =
            BigInteger.valueOf(-121665).multiply(inv(BigInteger.valueOf(121666))).mod(P);
    private static final BigInteger I = // sqrt(-1) mod p
            TWO.modPow(P.subtract(BigInteger.ONE).divide(BigInteger.valueOf(4)), P);

    record Point(BigInteger x, BigInteger y) {}

    static final Point ZERO = new Point(BigInteger.ZERO, BigInteger.ONE);
    static final Point B = basePoint();

    private static Point basePoint() {
        BigInteger by = BigInteger.valueOf(4).multiply(inv(BigInteger.valueOf(5))).mod(P);
        BigInteger bx = recoverX(by, 0);
        return new Point(bx, by);
    }

    private static BigInteger inv(BigInteger a) {
        return a.modPow(P.subtract(TWO), P);
    }

    private static BigInteger m(BigInteger a, BigInteger b) {
        return a.multiply(b).mod(P);
    }

    static Point add(Point p1, Point p2) {
        BigInteger x1y2 = m(p1.x, p2.y);
        BigInteger y1x2 = m(p1.y, p2.x);
        BigInteger y1y2 = m(p1.y, p2.y);
        BigInteger x1x2 = m(p1.x, p2.x);
        BigInteger dxxyy = m(D, m(x1x2, y1y2));
        BigInteger x3 = m(x1y2.add(y1x2), inv(BigInteger.ONE.add(dxxyy)));
        BigInteger y3 = m(y1y2.add(x1x2), inv(BigInteger.ONE.subtract(dxxyy).mod(P)));
        return new Point(x3, y3);
    }

    static Point negate(Point pt) {
        return new Point(P.subtract(pt.x).mod(P), pt.y);
    }

    /** n * pt via double-and-add (n treated as a non-negative integer). */
    static Point mul(BigInteger n, Point pt) {
        Point result = ZERO;
        Point addend = pt;
        BigInteger k = n;
        while (k.signum() > 0) {
            if (k.testBit(0)) {
                result = add(result, addend);
            }
            addend = add(addend, addend);
            k = k.shiftRight(1);
        }
        return result;
    }

    static Point mulBase(BigInteger n) {
        return mul(n, B);
    }

    static boolean isIdentity(Point pt) {
        return pt.x.signum() == 0 && pt.y.equals(BigInteger.ONE);
    }

    /** True iff pt is in the prime-order subgroup (L * pt == identity). */
    static boolean isOnMainSubgroup(Point pt) {
        return isIdentity(mul(L, pt));
    }

    /**
     * True iff pt has order dividing 8 (the curve's cofactor) — the identity
     * itself, or one of the 2-, 4-, or 8-torsion points. gcd(L, 8) = 1, so this
     * is the complementary test to {@link #isOnMainSubgroup}: a full-order
     * point never satisfies it, and a low-order point never satisfies
     * {@code isOnMainSubgroup} unless it happens to be the identity (for which
     * both are trivially true). Signature verification must reject these: with
     * a small-order public key A (in the limit, A = identity), [k]A takes only
     * as many distinct values as A's order, which is enough to satisfy the
     * verification equation for an attacker-chosen message without knowing any
     * private key.
     */
    static boolean isSmallOrder(Point pt) {
        return isIdentity(mul(BigInteger.valueOf(8), pt));
    }

    // --- Encoding ------------------------------------------------------------

    static byte[] encode(Point pt) {
        byte[] out = toLittleEndian(pt.y, 32);
        if (pt.x.testBit(0)) {
            out[31] = (byte) (out[31] | 0x80); // sign bit = x parity
        }
        return out;
    }

    /** RFC 8032 point decoding. Returns null if the bytes are not a curve point. */
    static Point decode(byte[] bytes) {
        if (bytes.length != 32) {
            return null;
        }
        byte[] b = bytes.clone();
        int sign = (b[31] & 0x80) >>> 7;
        b[31] = (byte) (b[31] & 0x7f);
        BigInteger y = fromLittleEndian(b);
        if (y.compareTo(P) >= 0) {
            return null; // non-canonical y
        }
        BigInteger x = recoverX(y, sign);
        return x == null ? null : new Point(x, y);
    }

    /** Recover x from y and the sign bit (RFC 8032 §5.1.3). Null if no root. */
    private static BigInteger recoverX(BigInteger y, int sign) {
        BigInteger y2 = m(y, y);
        BigInteger u = y2.subtract(BigInteger.ONE).mod(P);
        BigInteger v = m(D, y2).add(BigInteger.ONE).mod(P);
        BigInteger v3 = m(m(v, v), v);
        BigInteger v7 = m(m(v3, v3), v);
        BigInteger exp = P.subtract(BigInteger.valueOf(5)).divide(BigInteger.valueOf(8));
        BigInteger x = m(m(u, v3), u.multiply(v7).mod(P).modPow(exp, P));
        BigInteger vx2 = m(v, m(x, x));
        if (vx2.equals(u)) {
            // x is a square root
        } else if (vx2.equals(P.subtract(u).mod(P))) {
            x = m(x, I);
        } else {
            return null; // no square root -> off curve
        }
        if (x.signum() == 0 && sign == 1) {
            return null; // (0, y) with sign 1 is invalid
        }
        if ((x.testBit(0) ? 1 : 0) != sign) {
            x = P.subtract(x).mod(P);
        }
        return x;
    }

    /**
     * RFC 7748 §4.1 birational map, Edwards {@code y} to Montgomery {@code u}:
     * {@code u = (1+y) / (1-y) mod p}. This is the field-arithmetic half of
     * converting an Ed25519 public key to its X25519 counterpart.
     */
    static byte[] montgomeryU(BigInteger y) {
        BigInteger u = BigInteger.ONE.add(y).multiply(inv(BigInteger.ONE.subtract(y).mod(P))).mod(P);
        return toLittleEndian(u, 32);
    }

    private static byte[] toLittleEndian(BigInteger n, int len) {
        byte[] out = new byte[len];
        BigInteger v = n.mod(P);
        for (int i = 0; i < len; i++) {
            out[i] = (byte) v.and(BigInteger.valueOf(0xff)).intValue();
            v = v.shiftRight(8);
        }
        return out;
    }

    private static BigInteger fromLittleEndian(byte[] bytes) {
        BigInteger v = BigInteger.ZERO;
        for (int i = bytes.length - 1; i >= 0; i--) {
            v = v.shiftLeft(8).or(BigInteger.valueOf(bytes[i] & 0xff));
        }
        return v;
    }

    // --- Scalars (little-endian, mod L) --------------------------------------

    static BigInteger scalarFromLE(byte[] bytes) {
        return fromLittleEndian(bytes);
    }

    static byte[] scalarToLE32(BigInteger n) {
        byte[] out = new byte[32];
        BigInteger v = n.mod(L);
        for (int i = 0; i < 32; i++) {
            out[i] = (byte) v.and(BigInteger.valueOf(0xff)).intValue();
            v = v.shiftRight(8);
        }
        return out;
    }
}

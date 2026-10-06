package tech.hearth.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import tech.hearth.crypto.Ed25519Math.Point;

/**
 * Pure-JVM implementation of {@link CryptoBackend}: JDK digests, HMAC and Ed25519,
 * plus the BigInteger edwards25519 arithmetic in {@link Ed25519Math} for the raw
 * point and scalar operations. Produces byte-for-byte the same Ed25519 signatures
 * (RFC 8032) and ECVRF proofs (RFC 9381) as the libsodium backend, and accepts
 * exactly the signatures it accepts, so it is a drop-in fallback. Signing and
 * verification are the JDK's constant-time implementation; the point and scalar
 * operations are not constant-time.
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

    // Ed25519 itself is the JDK's (SunEC, RFC 8032, constant-time field arithmetic, ~500x faster than Ed25519Math).
    // Ed25519Math stays for the raw point and scalar operations below, which the ECVRF needs and the JDK does not expose.
    private static final String JDK_PROVIDER = "SunEC";
    private static final ThreadLocal<Signature> ED25519 =
            ThreadLocal.withInitial(() -> jdk(() -> Signature.getInstance("Ed25519", JDK_PROVIDER)));
    private static final ThreadLocal<KeyFactory> ED25519_KEYS =
            ThreadLocal.withInitial(() -> jdk(() -> KeyFactory.getInstance("Ed25519", JDK_PROVIDER)));
    private static final ThreadLocal<KeyPairGenerator> ED25519_KEYGEN =
            ThreadLocal.withInitial(() -> jdk(() -> KeyPairGenerator.getInstance("Ed25519", JDK_PROVIDER)));

    /**
     * The y of every small-order point (0, 1, p-1 and the two order-8 values) plus the non-canonical p and p+1, as
     * little-endian encodings without the x sign bit - libsodium's own blocklist. A y alone decides it: the
     * small-order points are closed under negation, so both signs of x are on the list.
     */
    static final List<byte[]> SMALL_ORDER_Y;

    static {
        BigInteger p = Ed25519Math.P;
        BigInteger y8 = new BigInteger("2707385501144840649318225287225658788936804267575313519463743609750303402022");
        SMALL_ORDER_Y = Stream.of(BigInteger.ZERO, BigInteger.ONE, p.subtract(BigInteger.ONE), y8, p.subtract(y8), p,
                        p.add(BigInteger.ONE))
                .map(JvmBackend::littleEndian32)
                .toList();
    }

    @Override
    public RawKeypair signSeedKeypair(byte[] seed) {
        if (seed.length != 32) {
            throw new IllegalArgumentException("seed must be 32 bytes");
        }
        byte[] pk = publicKeyOf(seed);
        return new RawKeypair(pk, concat(seed, pk));
    }

    @Override
    public byte[] signDetached(byte[] msg, byte[] secretKey) {
        if (secretKey.length != 64) {
            throw new IllegalArgumentException("secret key must be 64 bytes");
        }
        byte[] seed = Arrays.copyOfRange(secretKey, 0, 32);
        byte[] pub = Arrays.copyOfRange(secretKey, 32, 64);
        // libsodium hashes the public half it is handed, the JDK re-derives it from the seed. They part only on a
        // secret key whose halves do not belong together, which must still sign like libsodium does.
        if (!Arrays.equals(pub, publicKeyOf(seed))) {
            return signWithMath(msg, seed, pub);
        }
        try {
            Signature signer = ED25519.get();
            signer.initSign(ED25519_KEYS.get().generatePrivate(new EdECPrivateKeySpec(NamedParameterSpec.ED25519, seed)));
            signer.update(msg);
            return signer.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private byte[] signWithMath(byte[] msg, byte[] seed, byte[] pub) {
        byte[] h = sha512(seed);
        BigInteger a = Ed25519Math.scalarFromLE(clamp(sliceHash(h)));
        byte[] prefix = Arrays.copyOfRange(h, 32, 64);
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
        // The JDK enforces what libsodium does - s < L, canonical A and R, the cofactorless equation - except this:
        // a small-order A or R makes [k]A (or the R term) take too few values, so a signature can be forged for a
        // chosen message without any private key.
        if (hasSmallOrderY(publicKey, 0) || hasSmallOrderY(sig, 0)) {
            return false;
        }
        try {
            Signature verifier = ED25519.get();
            verifier.initVerify(ED25519_KEYS.get().generatePublic(
                    new EdECPublicKeySpec(NamedParameterSpec.ED25519, pointOf(publicKey))));
            verifier.update(msg);
            return verifier.verify(sig);
        } catch (InvalidKeyException | InvalidKeySpecException | SignatureException e) {
            return false; // not a point, non-canonical, or s >= L
        }
    }

    static boolean hasSmallOrderY(byte[] encoded, int offset) {
        for (byte[] y : SMALL_ORDER_Y) {
            if (Arrays.equals(encoded, offset, offset + 31, y, 0, 31) && (encoded[offset + 31] & 0x7f) == y[31]) {
                return true;
            }
        }
        return false;
    }

    private static EdECPoint pointOf(byte[] encoded) {
        byte[] y = encoded.clone();
        boolean xOdd = (y[31] & 0x80) != 0;
        y[31] &= 0x7f;
        return new EdECPoint(xOdd, Ed25519Math.scalarFromLE(y));
    }

    // The JDK derives a public key only inside key generation, so it gets the seed as its "randomness".
    private static byte[] publicKeyOf(byte[] seed) {
        KeyPairGenerator keygen = ED25519_KEYGEN.get();
        try {
            keygen.initialize(NamedParameterSpec.ED25519, new SeedAsRandomness(seed));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
        EdECPoint point = ((EdECPublicKey) keygen.generateKeyPair().getPublic()).getPoint();
        byte[] encoded = littleEndian32(point.getY());
        if (point.isXOdd()) {
            encoded[31] |= (byte) 0x80;
        }
        return encoded;
    }

    // Unreduced, unlike Ed25519Math's encoders: the blocklist holds the non-canonical p and p+1 as well.
    private static byte[] littleEndian32(BigInteger n) {
        byte[] out = new byte[32];
        for (int i = 0; i < 32; i++) {
            out[i] = n.shiftRight(8 * i).byteValue();
        }
        return out;
    }

    private static final class SeedAsRandomness extends SecureRandom {
        private final byte[] seed;

        SeedAsRandomness(byte[] seed) {
            this.seed = seed;
        }

        @Override
        public void nextBytes(byte[] bytes) {
            if (bytes.length != seed.length) {
                throw new IllegalStateException("Ed25519 key generation asked for " + bytes.length + " random bytes");
            }
            System.arraycopy(seed, 0, bytes, 0, bytes.length);
        }
    }

    private interface JdkCall<T> {
        T call() throws GeneralSecurityException;
    }

    // Ed25519 is in every JDK since 15, so its absence is a broken runtime, not a condition to handle.
    private static <T> T jdk(JdkCall<T> call) {
        try {
            return call.call();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
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

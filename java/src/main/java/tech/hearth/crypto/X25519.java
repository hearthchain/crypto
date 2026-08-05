package tech.hearth.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;

import javax.crypto.KeyAgreement;

/**
 * X25519 (RFC 7748) over raw 32-byte little-endian keys — the Diffie-Hellman
 * half of {@link Hpke}'s DHKEM.
 *
 * <p>Unlike the rest of the library this does <em>not</em> go through
 * {@link CryptoBackend}: neither backend exposes Montgomery-curve scalar
 * multiplication ({@code JvmBackend}'s {@code BigInteger} group is edwards25519
 * only). It runs on the JDK's built-in XDH provider instead, which is native
 * constant-time code in SunEC and needs no dependency.
 *
 * <p>Keys are handled in the wire encoding RFC 7748 and RFC 9180 use: 32 bytes,
 * little-endian, unclamped (X25519 clamps the scalar internally).
 */
public final class X25519 {
    private X25519() {}

    /** Size of both a private scalar and a public u-coordinate. */
    public static final int KEY_BYTES = 32;

    private static final String ALGORITHM = "X25519";

    /** u = 9, the RFC 7748 base point, little-endian. */
    private static final byte[] BASE_POINT = basePoint();

    private static final SecureRandom RANDOM = new SecureRandom();

    /** An X25519 keypair in raw little-endian form. */
    public record Keypair(byte[] publicKey, byte[] secretKey) {}

    /** A fresh keypair from the shared {@link SecureRandom}. */
    public static Keypair generateKeypair() {
        return generateKeypair(RANDOM);
    }

    /**
     * A fresh keypair. The secret is 32 uniformly random bytes; X25519 clamps
     * them when they are used, so every draw is a valid scalar.
     */
    public static Keypair generateKeypair(SecureRandom random) {
        byte[] sk = new byte[KEY_BYTES];
        random.nextBytes(sk);
        return new Keypair(publicKey(sk), sk);
    }

    /** The public key for a secret scalar, i.e. X25519(sk, 9). */
    public static byte[] publicKey(byte[] secretKey) {
        return scalarMult(secretKey, BASE_POINT);
    }

    /**
     * The Diffie-Hellman shared coordinate X25519(sk, pk).
     *
     * @throws IllegalArgumentException if {@code publicKey} has small order (an
     *         all-zero result), which RFC 9180 §7.1.4 requires KEMs to reject.
     */
    public static byte[] dh(byte[] secretKey, byte[] publicKey) {
        return scalarMult(secretKey, publicKey);
    }

    private static byte[] scalarMult(byte[] secretKey, byte[] point) {
        if (secretKey.length != KEY_BYTES) {
            throw new IllegalArgumentException("X25519 secret key must be " + KEY_BYTES + " bytes");
        }
        if (point.length != KEY_BYTES) {
            throw new IllegalArgumentException("X25519 public key must be " + KEY_BYTES + " bytes");
        }
        KeyFactory factory;
        KeyAgreement agreement;
        try {
            factory = KeyFactory.getInstance(ALGORITHM);
            agreement = KeyAgreement.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("no X25519 provider on this JDK", e);
        }
        try {
            PrivateKey sk = factory.generatePrivate(
                    new XECPrivateKeySpec(NamedParameterSpec.X25519, secretKey.clone()));
            PublicKey pk = factory.generatePublic(
                    new XECPublicKeySpec(NamedParameterSpec.X25519, decodeU(point)));

            agreement.init(sk);
            agreement.doPhase(pk, true);
            byte[] shared = agreement.generateSecret();

            // SunEC already rejects small-order points; re-check so the contract
            // holds on any provider.
            if (isAllZero(shared)) {
                Arrays.fill(shared, (byte) 0);
                throw new IllegalArgumentException("X25519: public key has small order");
            }
            return shared;
        } catch (GeneralSecurityException e) {
            // A small-order point surfaces here on SunEC ("Point has small order").
            throw new IllegalArgumentException("X25519 scalar multiplication failed", e);
        }
    }

    /** Wire bytes (little-endian, MSB ignored per RFC 7748 §5) to the u-coordinate. */
    private static BigInteger decodeU(byte[] point) {
        byte[] be = new byte[KEY_BYTES];
        for (int i = 0; i < KEY_BYTES; i++) {
            be[i] = point[KEY_BYTES - 1 - i];
        }
        be[0] &= 0x7f;
        return new BigInteger(1, be);
    }

    private static boolean isAllZero(byte[] value) {
        int acc = 0;
        for (byte b : value) {
            acc |= b;
        }
        return acc == 0;
    }

    private static byte[] basePoint() {
        byte[] u = new byte[KEY_BYTES];
        u[0] = 9;
        return u;
    }
}

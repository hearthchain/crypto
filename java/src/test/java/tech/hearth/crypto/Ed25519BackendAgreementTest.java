package tech.hearth.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Every node must accept exactly the signatures every other node accepts, whichever backend it runs on, or a block
 * valid on one platform is invalid on another. libsodium is the reference: the JVM backend has to sign byte for byte
 * like it and agree with its verdict on every input, including the ones RFC 8032 leaves open (small-order points,
 * non-canonical encodings), where libsodium is stricter than the RFC.
 */
class Ed25519BackendAgreementTest {

    private static SodiumBackend sodium;
    private static final JvmBackend jvm = JvmBackend.INSTANCE;
    private static final Random random = new Random(20261006L);

    @BeforeAll
    static void loadSodium() {
        try {
            sodium = new SodiumBackend();
            sodium.selfTest();
        } catch (Throwable t) {
            sodium = null;
        }
    }

    private static void requireSodium() {
        assumeTrue(sodium != null, "libsodium not available, nothing to agree with");
    }

    private static byte[] bytes(int n) {
        byte[] b = new byte[n];
        random.nextBytes(b);
        return b;
    }

    private static void assertSameVerdict(byte[] sig, byte[] msg, byte[] pk) {
        assertEquals(sodium.verifyDetached(sig, msg, pk), jvm.verifyDetached(sig, msg, pk),
                () -> "sig=" + Hex.encode(sig) + " pk=" + Hex.encode(pk));
    }

    /** Little-endian 32-byte encoding of y, with the x sign bit set as asked. */
    private static byte[] encoding(BigInteger y, boolean xOdd) {
        byte[] le = new byte[32];
        byte[] be = y.toByteArray();
        for (int i = 0; i < be.length && i < 32; i++) {
            le[i] = be[be.length - 1 - i];
        }
        if (xOdd) {
            le[31] |= (byte) 0x80;
        }
        return le;
    }

    /**
     * Every y of the eight small-order points (0, 1, p-1 and the two order-8 values), each with both sign bits, plus
     * the non-canonical encodings p and p+1 of 0 and 1.
     */
    private static List<byte[]> smallOrderEncodings() {
        BigInteger p = Ed25519Math.P;
        BigInteger y8 = new BigInteger(
                "2707385501144840649318225287225658788936804267575313519463743609750303402022");
        List<byte[]> out = new ArrayList<>();
        for (BigInteger y : List.of(BigInteger.ZERO, BigInteger.ONE, p.subtract(BigInteger.ONE), y8, p.subtract(y8),
                p, p.add(BigInteger.ONE))) {
            out.add(encoding(y, false));
            out.add(encoding(y, true));
        }
        return out;
    }

    @Test
    void smallOrderFixtureIsSmallOrder() {
        BigInteger p = Ed25519Math.P;
        for (byte[] enc : smallOrderEncodings()) {
            Ed25519Math.Point pt = Ed25519Math.decode(enc);
            BigInteger y = new BigInteger(1, reversed(masked(enc)));
            // non-canonical or sign-bit-on-x=0 encodings do not decode at all, which is fine: they must be rejected too
            if (pt != null) {
                assertEquals(true, Ed25519Math.isSmallOrder(pt), Hex.encode(enc));
            } else {
                assertEquals(true, y.compareTo(p) >= 0 || y.equals(BigInteger.ONE) || y.equals(p.subtract(BigInteger.ONE)),
                        Hex.encode(enc));
            }
        }
    }

    // JvmBackend's own blocklist, checked without libsodium: the JDK alone would accept these.
    @Test
    void jvmBlocklistCoversEverySmallOrderEncoding() {
        for (byte[] enc : smallOrderEncodings()) {
            assertEquals(true, JvmBackend.hasSmallOrderY(enc, 0), Hex.encode(enc));
        }
        for (int i = 0; i < 200; i++) {
            byte[] pk = jvm.signSeedKeypair(bytes(32)).publicKey();
            assertFalse(JvmBackend.hasSmallOrderY(pk, 0), Hex.encode(pk));
        }
    }

    @Test
    void derivesTheSameKeypairs() {
        requireSodium();
        for (int i = 0; i < 200; i++) {
            byte[] seed = bytes(32);
            CryptoBackend.RawKeypair s = sodium.signSeedKeypair(seed);
            CryptoBackend.RawKeypair j = jvm.signSeedKeypair(seed);
            assertArrayEquals(s.publicKey(), j.publicKey());
            assertArrayEquals(s.secretKey(), j.secretKey());
        }
    }

    @Test
    void signsTheSameBytes() {
        requireSodium();
        for (int i = 0; i < 200; i++) {
            byte[] sk = sodium.signSeedKeypair(bytes(32)).secretKey();
            byte[] msg = bytes(random.nextInt(300));
            assertArrayEquals(sodium.signDetached(msg, sk), jvm.signDetached(msg, sk));
        }
    }

    // libsodium hashes the public half it is handed rather than re-deriving it, so a mismatched half changes the bytes.
    @Test
    void signsTheSameBytesWithAMismatchedPublicHalf() {
        requireSodium();
        byte[] sk = sodium.signSeedKeypair(bytes(32)).secretKey();
        System.arraycopy(bytes(32), 0, sk, 32, 32);
        byte[] msg = "mismatched".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(sodium.signDetached(msg, sk), jvm.signDetached(msg, sk));
    }

    @Test
    void agreesOnValidAndTamperedSignatures() {
        requireSodium();
        for (int i = 0; i < 200; i++) {
            CryptoBackend.RawKeypair kp = sodium.signSeedKeypair(bytes(32));
            byte[] msg = bytes(1 + random.nextInt(300));
            byte[] sig = sodium.signDetached(msg, kp.secretKey());
            assertSameVerdict(sig, msg, kp.publicKey());

            byte[] badSig = sig.clone();
            badSig[random.nextInt(64)] ^= (byte) (1 << random.nextInt(8));
            assertSameVerdict(badSig, msg, kp.publicKey());

            byte[] badMsg = msg.clone();
            badMsg[random.nextInt(badMsg.length)] ^= 1;
            assertSameVerdict(sig, badMsg, kp.publicKey());

            byte[] badPk = kp.publicKey().clone();
            badPk[random.nextInt(32)] ^= (byte) (1 << random.nextInt(8));
            assertSameVerdict(sig, msg, badPk);
        }
    }

    @Test
    void agreesOnArbitraryBytes() {
        requireSodium();
        for (int i = 0; i < 500; i++) {
            assertSameVerdict(bytes(64), bytes(32), bytes(32));
        }
    }

    // S + L verifies under the bare equation, so only the s < L check rejects it.
    @Test
    void agreesOnANonCanonicalS() {
        requireSodium();
        CryptoBackend.RawKeypair kp = sodium.signSeedKeypair(bytes(32));
        byte[] msg = "malleable".getBytes(StandardCharsets.UTF_8);
        byte[] sig = sodium.signDetached(msg, kp.secretKey());
        BigInteger s = new BigInteger(1, reversed(Arrays.copyOfRange(sig, 32, 64))).add(Ed25519Math.L);
        byte[] malleated = sig.clone();
        System.arraycopy(encoding(s, false), 0, malleated, 32, 32);
        assertSameVerdict(malleated, msg, kp.publicKey());
        assertFalse(jvm.verifyDetached(malleated, msg, kp.publicKey()));
    }

    @Test
    void agreesOnSmallOrderPublicKeysAndR() {
        requireSodium();
        CryptoBackend.RawKeypair kp = sodium.signSeedKeypair(bytes(32));
        byte[] msg = "small order".getBytes(StandardCharsets.UTF_8);
        byte[] sig = sodium.signDetached(msg, kp.secretKey());
        for (byte[] enc : smallOrderEncodings()) {
            assertSameVerdict(sig, msg, enc);
            assertFalse(jvm.verifyDetached(sig, msg, enc), Hex.encode(enc));

            byte[] withR = sig.clone();
            System.arraycopy(enc, 0, withR, 0, 32);
            assertSameVerdict(withR, msg, kp.publicKey());
            assertFalse(jvm.verifyDetached(withR, msg, kp.publicKey()), Hex.encode(enc));

            // R = A = the small-order point and S = 0 satisfies [S]B = R + [k]A for every k: a universal forgery
            byte[] forged = new byte[64];
            System.arraycopy(enc, 0, forged, 0, 32);
            assertSameVerdict(forged, msg, enc);
            assertFalse(jvm.verifyDetached(forged, msg, enc), Hex.encode(enc));
        }
    }

    private static byte[] masked(byte[] enc) {
        byte[] b = enc.clone();
        b[31] &= 0x7f;
        return b;
    }

    private static byte[] reversed(byte[] b) {
        byte[] r = new byte[b.length];
        for (int i = 0; i < b.length; i++) {
            r[i] = b[b.length - 1 - i];
        }
        return r;
    }
}

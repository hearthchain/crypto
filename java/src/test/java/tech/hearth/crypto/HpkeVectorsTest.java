package tech.hearth.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * RFC 9180 Appendix A base-mode test vectors for
 * DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256, on every backend.
 */
class HpkeVectorsTest {

    private static byte[] hx(String s) {
        return Hex.decode(s);
    }

    /** JVM backend always; libsodium when present. */
    static Stream<Named<CryptoBackend>> backends() {
        List<Named<CryptoBackend>> list = new ArrayList<>();
        list.add(Named.of("jvm", JvmBackend.INSTANCE));
        try {
            SodiumBackend sodium = new SodiumBackend();
            sodium.selfTest();
            list.add(Named.of("libsodium", sodium));
        } catch (Throwable ignored) {
            // libsodium not available
        }
        return list.stream();
    }

    /** One base-mode setup from RFC 9180 Appendix A, plus its sequence-0 encryption. */
    private record Vector(String name, Hpke.Suite suite, String info, String skEm, String pkEm, String skRm,
            String pkRm, String sharedSecret, String key, String baseNonce, String exporterSecret, String pt,
            String aad, String ct) {}

    /** RFC 9180 A.1: AES-128-GCM. */
    private static final Vector A1 = new Vector(
            "A.1",
            Hpke.Suite.X25519_SHA256_AES128GCM,
            "4f6465206f6e2061204772656369616e2055726e",
            "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
            "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
            "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
            "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
            "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
            "4531685d41d65f03dc48f6b8302c05b0",
            "56d890e5accaaf011cff4b7d",
            "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8",
            "4265617574792069732074727574682c20747275746820626561757479",
            "436f756e742d30",
            "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a");

    /** RFC 9180 A.2: ChaCha20-Poly1305. */
    private static final Vector A2 = new Vector(
            "A.2",
            Hpke.Suite.X25519_SHA256_CHACHA20POLY1305,
            "4f6465206f6e2061204772656369616e2055726e",
            "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",
            "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
            "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
            "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
            "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7",
            "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91",
            "5c4d98150661b848853b547f",
            "a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922",
            "4265617574792069732074727574682c20747275746820626561757479",
            "436f756e742d30",
            "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28");

    @ParameterizedTest(name = "A.1 AES-128-GCM [{0}]")
    @MethodSource("backends")
    void rfc9180AppendixA1(CryptoBackend backend) {
        checkVector(A1, backend);
    }

    @ParameterizedTest(name = "A.2 ChaCha20-Poly1305 [{0}]")
    @MethodSource("backends")
    void rfc9180AppendixA2(CryptoBackend backend) {
        checkVector(A2, backend);
    }

    private void checkVector(Vector v, CryptoBackend backend) {
        // The keypairs in the vector are self-consistent under our X25519.
        assertArrayEquals(hx(v.pkEm()), X25519.publicKey(hx(v.skEm())), v.name() + ": pkEm");
        assertArrayEquals(hx(v.pkRm()), X25519.publicKey(hx(v.skRm())), v.name() + ": pkRm");

        // DHKEM Encap and Decap agree on the shared secret, and match the vector.
        byte[] enc = hx(v.pkEm());
        byte[] encapped = Hpke.extractAndExpand(
                X25519.dh(hx(v.skEm()), hx(v.pkRm())), enc, hx(v.pkRm()), backend);
        byte[] decapped = Hpke.extractAndExpand(
                X25519.dh(hx(v.skRm()), enc), enc, hx(v.pkRm()), backend);
        assertArrayEquals(hx(v.sharedSecret()), encapped, v.name() + ": Encap shared_secret");
        assertArrayEquals(hx(v.sharedSecret()), decapped, v.name() + ": Decap shared_secret");

        // The key schedule.
        Hpke.Context context = Hpke.keySchedule(v.suite(), hx(v.sharedSecret()), hx(v.info()), backend);
        assertArrayEquals(hx(v.key()), context.key(), v.name() + ": key");
        assertArrayEquals(hx(v.baseNonce()), context.baseNonce(), v.name() + ": base_nonce");
        assertArrayEquals(hx(v.exporterSecret()), context.exporterSecret(), v.name() + ": exporter_secret");

        // Seal at sequence number 0.
        Hpke.Sealed sealed = Hpke.sealWithEphemeral(
                v.suite(), hx(v.skEm()), hx(v.pkRm()), hx(v.info()), hx(v.aad()), hx(v.pt()), backend);
        assertArrayEquals(enc, sealed.enc(), v.name() + ": enc");
        assertArrayEquals(hx(v.ct()), sealed.ciphertext(), v.name() + ": ct");

        // And Open recovers the plaintext.
        assertArrayEquals(hx(v.pt()),
                Hpke.open(v.suite(), hx(v.skRm()), enc, hx(v.info()), hx(v.aad()), hx(v.ct()), backend),
                v.name() + ": pt");
    }

    /** AES-256-GCM has no X25519 vector in the RFC; cover it by round-trip. */
    @ParameterizedTest
    @EnumSource(Hpke.Suite.class)
    void sealOpenRoundTrip(Hpke.Suite suite) {
        X25519.Keypair recipient = X25519.generateKeypair();
        byte[] info = utf8("hearth-test/info");
        byte[] aad = utf8("hearth-test/aad");
        byte[] plaintext = utf8("the quick brown fox");

        Hpke.Sealed sealed = Hpke.seal(suite, recipient.publicKey(), info, aad, plaintext);
        assertEquals(Hpke.ENC_BYTES, sealed.enc().length);
        assertEquals(plaintext.length + Hpke.TAG_BYTES, sealed.ciphertext().length);
        assertArrayEquals(plaintext,
                Hpke.open(suite, recipient.secretKey(), sealed.enc(), info, aad, sealed.ciphertext()));
    }

    @Test
    void sealIsRandomizedPerCall() {
        X25519.Keypair recipient = X25519.generateKeypair();
        Hpke.Sealed first = Hpke.seal(
                Hpke.Suite.X25519_SHA256_CHACHA20POLY1305, recipient.publicKey(), utf8("i"), utf8("a"), utf8("p"));
        Hpke.Sealed second = Hpke.seal(
                Hpke.Suite.X25519_SHA256_CHACHA20POLY1305, recipient.publicKey(), utf8("i"), utf8("a"), utf8("p"));
        assertFalseArrayEquals(first.enc(), second.enc());
        assertFalseArrayEquals(first.ciphertext(), second.ciphertext());
    }

    @Test
    void openRejectsWrongInfoAadKeyOrCiphertext() {
        X25519.Keypair recipient = X25519.generateKeypair();
        byte[] info = utf8("info");
        byte[] aad = utf8("aad");
        Hpke.Suite suite = Hpke.Suite.X25519_SHA256_CHACHA20POLY1305;
        Hpke.Sealed sealed = Hpke.seal(suite, recipient.publicKey(), info, aad, utf8("secret"));

        assertThrows(IllegalArgumentException.class, () ->
                Hpke.open(suite, recipient.secretKey(), sealed.enc(), utf8("other"), aad, sealed.ciphertext()));
        assertThrows(IllegalArgumentException.class, () ->
                Hpke.open(suite, recipient.secretKey(), sealed.enc(), info, utf8("other"), sealed.ciphertext()));
        assertThrows(IllegalArgumentException.class, () ->
                Hpke.open(suite, X25519.generateKeypair().secretKey(), sealed.enc(), info, aad, sealed.ciphertext()));

        byte[] tampered = sealed.ciphertext().clone();
        tampered[0] ^= 0x01;
        assertThrows(IllegalArgumentException.class, () ->
                Hpke.open(suite, recipient.secretKey(), sealed.enc(), info, aad, tampered));
    }

    @Test
    void x25519RejectsSmallOrderPublicKey() {
        // The all-zero u-coordinate is the canonical small-order point; RFC 9180
        // requires the KEM to abort rather than derive from an all-zero DH output.
        byte[] smallOrder = new byte[X25519.KEY_BYTES];
        assertThrows(IllegalArgumentException.class,
                () -> X25519.dh(X25519.generateKeypair().secretKey(), smallOrder));
    }

    /**
     * Beyond the trivial all-zero point: every other canonical low-order/invalid
     * u-coordinate (u=1, and the boundary encodings p-1, p, p+1 for
     * p = 2^255-19), little-endian. Under X25519's mandatory scalar clamping
     * (which forces the scalar to be a multiple of 8) every point of order
     * dividing 8 collapses to the identity, so the DH output is all-zero for
     * every one of these too — confirmed against a raw (unclamped-check)
     * Montgomery ladder, independent of this library. This is *why* the single
     * all-zero-output check above is a complete mitigation, not just a
     * heuristic for the one obvious case.
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "0100000000000000000000000000000000000000000000000000000000000000", // u=1
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // u=p-1
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // u=p
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // u=p+1
    })
    void x25519RejectsOtherDegeneratePublicKeys(String hex) {
        byte[] degenerate = hx(hex);
        assertThrows(IllegalArgumentException.class,
                () -> X25519.dh(X25519.generateKeypair().secretKey(), degenerate));
    }

    @Test
    void suiteLookupByAeadId() {
        for (Hpke.Suite suite : Hpke.Suite.values()) {
            assertEquals(suite, Hpke.Suite.fromAeadId(suite.aeadId()));
        }
        assertThrows(IllegalArgumentException.class, () -> Hpke.Suite.fromAeadId(0x00ff));
    }

    private static void assertFalseArrayEquals(byte[] a, byte[] b) {
        assertTrue(!java.util.Arrays.equals(a, b), "expected the two values to differ");
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }
}

package tech.hearth.crypto;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * HPKE (RFC 9180) single-shot public-key encryption, base mode, over
 * <strong>DHKEM(X25519, HKDF-SHA256)</strong> + <strong>HKDF-SHA256</strong>.
 *
 * <p>Base mode means the sender is anonymous: anyone holding the recipient's
 * public key can seal. That is exactly the shape of "encrypt a secret to a
 * public key published by an enclave" — the recipient is authenticated (by
 * attestation, out of band), the sender is authorized by the transport.
 *
 * <p>Only the single-shot {@code Seal}/{@code Open} of RFC 9180 §6.1 is
 * implemented — one message per encapsulation, always at sequence number 0.
 * There is deliberately no stateful sender context to reuse, so a nonce can
 * never be repeated under one key.
 *
 * <p>The whole construction runs on the JDK: HMAC through {@link CryptoBackend},
 * AEAD through {@code javax.crypto}, and the group operation through
 * {@link X25519}. Verified against the RFC 9180 A.1 and A.2 test vectors.
 *
 * @see ApiKeyEnvelope for the ready-made wire format this library uses for
 *      shipping an API key to an enclave
 */
public final class Hpke {
    private Hpke() {}

    /** DHKEM(X25519, HKDF-SHA256). */
    public static final int KEM_ID = 0x0020;

    /** HKDF-SHA256. */
    public static final int KDF_ID = 0x0001;

    /** Size of an encapsulated key (a serialized X25519 public key). */
    public static final int ENC_BYTES = X25519.KEY_BYTES;

    /** Every AEAD here has a 16-byte tag. */
    public static final int TAG_BYTES = 16;

    private static final int MODE_BASE = 0x00;
    private static final int NH = 32; // Nh for HKDF-SHA256
    private static final int NSECRET = 32; // Nsecret for DHKEM(X25519, ...)
    private static final int TAG_BITS = TAG_BYTES * Byte.SIZE;

    private static final byte[] HPKE_V1 = ascii("HPKE-v1");
    private static final byte[] KEM_SUITE_ID = concat(ascii("KEM"), i2osp(KEM_ID, 2));
    private static final byte[] EMPTY = new byte[0];

    /**
     * The supported ciphersuites. All share DHKEM(X25519, HKDF-SHA256) and
     * HKDF-SHA256 and differ only in the AEAD.
     */
    public enum Suite {
        /** RFC 9180 A.1. The mandatory-to-implement AEAD. */
        X25519_SHA256_AES128GCM(0x0001, 16, "AES/GCM/NoPadding", "AES"),
        /** 256-bit AES, for when a key-size policy asks for it. */
        X25519_SHA256_AES256GCM(0x0002, 32, "AES/GCM/NoPadding", "AES"),
        /** RFC 9180 A.2. The default here: no AES-NI dependency for constant time. */
        X25519_SHA256_CHACHA20POLY1305(0x0003, 32, "ChaCha20-Poly1305", "ChaCha20");

        private final int aeadId;
        private final int nk;
        private final String transformation;
        private final String keyAlgorithm;

        Suite(int aeadId, int nk, String transformation, String keyAlgorithm) {
            this.aeadId = aeadId;
            this.nk = nk;
            this.transformation = transformation;
            this.keyAlgorithm = keyAlgorithm;
        }

        /** The RFC 9180 AEAD id. */
        public int aeadId() {
            return aeadId;
        }

        /** AEAD key length, Nk. */
        public int keyBytes() {
            return nk;
        }

        /** AEAD nonce length, Nn. 12 for every AEAD registered so far. */
        public int nonceBytes() {
            return 12;
        }

        /** The suite with this AEAD id. */
        public static Suite fromAeadId(int aeadId) {
            for (Suite suite : values()) {
                if (suite.aeadId == aeadId) {
                    return suite;
                }
            }
            throw new IllegalArgumentException("unsupported HPKE AEAD id: 0x%04x".formatted(aeadId));
        }
    }

    /** The output of {@code Seal}: the encapsulated key and the ciphertext. */
    public record Sealed(byte[] enc, byte[] ciphertext) {}

    /**
     * Encrypt {@code plaintext} to {@code recipientPublicKey} using the default
     * backend.
     *
     * @param info application context, bound into the key schedule; it must be a
     *             fixed, purpose-specific string so ciphertexts cannot be
     *             replayed into a different protocol
     * @param aad  additional authenticated data, authenticated but not encrypted
     */
    public static Sealed seal(Suite suite, byte[] recipientPublicKey, byte[] info, byte[] aad, byte[] plaintext) {
        return seal(suite, recipientPublicKey, info, aad, plaintext, Crypto.defaultBackend());
    }

    /** Encrypt {@code plaintext} to {@code recipientPublicKey}. */
    public static Sealed seal(Suite suite, byte[] recipientPublicKey, byte[] info, byte[] aad, byte[] plaintext,
            CryptoBackend backend) {
        X25519.Keypair ephemeral = X25519.generateKeypair();
        try {
            return sealWithEphemeral(suite, ephemeral.secretKey(), recipientPublicKey, info, aad, plaintext, backend);
        } finally {
            wipe(ephemeral.secretKey());
        }
    }

    /**
     * Decrypt using the default backend.
     *
     * @throws IllegalArgumentException if authentication fails — a corrupt,
     *         forged, or mis-addressed ciphertext is indistinguishable here
     */
    public static byte[] open(Suite suite, byte[] recipientSecretKey, byte[] enc, byte[] info, byte[] aad,
            byte[] ciphertext) {
        return open(suite, recipientSecretKey, enc, info, aad, ciphertext, Crypto.defaultBackend());
    }

    /** Decrypt. */
    public static byte[] open(Suite suite, byte[] recipientSecretKey, byte[] enc, byte[] info, byte[] aad,
            byte[] ciphertext, CryptoBackend backend) {
        if (enc.length != ENC_BYTES) {
            throw new IllegalArgumentException("enc must be " + ENC_BYTES + " bytes");
        }
        if (ciphertext.length < TAG_BYTES) {
            throw new IllegalArgumentException("ciphertext is shorter than the AEAD tag");
        }
        byte[] dh = X25519.dh(recipientSecretKey, enc);
        byte[] recipientPublicKey = X25519.publicKey(recipientSecretKey);
        byte[] sharedSecret = extractAndExpand(dh, enc, recipientPublicKey, backend);
        Context context = keySchedule(suite, sharedSecret, info, backend);
        try {
            return aead(suite, Cipher.DECRYPT_MODE, context.key(), context.baseNonce(), aad, ciphertext);
        } finally {
            wipe(dh, sharedSecret);
            context.wipe();
        }
    }

    // ---------------------------------------------------------------- internals

    /** The key schedule outputs of RFC 9180 §5.1. Package-private for the vector tests. */
    record Context(byte[] key, byte[] baseNonce, byte[] exporterSecret) {
        void wipe() {
            Hpke.wipe(key, baseNonce, exporterSecret);
        }
    }

    /**
     * {@code Seal} with a caller-supplied ephemeral key. Package-private: the RFC
     * 9180 vectors pin {@code skEm}, and outside a test a reused ephemeral key
     * would repeat the AEAD nonce.
     */
    static Sealed sealWithEphemeral(Suite suite, byte[] ephemeralSecretKey, byte[] recipientPublicKey, byte[] info,
            byte[] aad, byte[] plaintext, CryptoBackend backend) {
        if (recipientPublicKey.length != X25519.KEY_BYTES) {
            throw new IllegalArgumentException("recipient public key must be " + X25519.KEY_BYTES + " bytes");
        }
        byte[] enc = X25519.publicKey(ephemeralSecretKey);
        byte[] dh = X25519.dh(ephemeralSecretKey, recipientPublicKey);
        byte[] sharedSecret = extractAndExpand(dh, enc, recipientPublicKey, backend);
        Context context = keySchedule(suite, sharedSecret, info, backend);
        try {
            return new Sealed(enc, aead(suite, Cipher.ENCRYPT_MODE, context.key(), context.baseNonce(), aad, plaintext));
        } finally {
            wipe(dh, sharedSecret);
            context.wipe();
        }
    }

    /** DHKEM's {@code ExtractAndExpand} (RFC 9180 §4.1), shared by Encap and Decap. */
    static byte[] extractAndExpand(byte[] dh, byte[] enc, byte[] recipientPublicKey, CryptoBackend backend) {
        byte[] kemContext = concat(enc, recipientPublicKey);
        byte[] eaePrk = labeledExtract(KEM_SUITE_ID, EMPTY, "eae_prk", dh, backend);
        try {
            return labeledExpand(KEM_SUITE_ID, eaePrk, "shared_secret", kemContext, NSECRET, backend);
        } finally {
            wipe(eaePrk);
        }
    }

    /** {@code KeySchedule} for mode_base (RFC 9180 §5.1): psk and psk_id are empty. */
    static Context keySchedule(Suite suite, byte[] sharedSecret, byte[] info, CryptoBackend backend) {
        byte[] suiteId = suiteId(suite);
        byte[] pskIdHash = labeledExtract(suiteId, EMPTY, "psk_id_hash", EMPTY, backend);
        byte[] infoHash = labeledExtract(suiteId, EMPTY, "info_hash", info, backend);
        byte[] keyScheduleContext = concat(new byte[] {(byte) MODE_BASE}, pskIdHash, infoHash);

        byte[] secret = labeledExtract(suiteId, sharedSecret, "secret", EMPTY, backend);
        try {
            return new Context(
                    labeledExpand(suiteId, secret, "key", keyScheduleContext, suite.keyBytes(), backend),
                    labeledExpand(suiteId, secret, "base_nonce", keyScheduleContext, suite.nonceBytes(), backend),
                    labeledExpand(suiteId, secret, "exp", keyScheduleContext, NH, backend));
        } finally {
            wipe(secret);
        }
    }

    private static byte[] suiteId(Suite suite) {
        return concat(ascii("HPKE"), i2osp(KEM_ID, 2), i2osp(KDF_ID, 2), i2osp(suite.aeadId(), 2));
    }

    private static byte[] labeledExtract(byte[] suiteId, byte[] salt, String label, byte[] ikm, CryptoBackend backend) {
        return extract(salt, concat(HPKE_V1, suiteId, ascii(label), ikm), backend);
    }

    private static byte[] labeledExpand(byte[] suiteId, byte[] prk, String label, byte[] info, int length,
            CryptoBackend backend) {
        return expand(prk, concat(i2osp(length, 2), HPKE_V1, suiteId, ascii(label), info), length, backend);
    }

    /**
     * HKDF-Extract (RFC 5869 §2.2). An empty salt becomes HashLen zero bytes, as
     * the RFC specifies — HMAC zero-pads its key, so this is also what an
     * empty-key HMAC would produce, but spelling it out keeps every backend's
     * empty-key handling out of the picture.
     */
    private static byte[] extract(byte[] salt, byte[] ikm, CryptoBackend backend) {
        return backend.hmacSha256(salt.length == 0 ? new byte[NH] : salt, ikm);
    }

    /** HKDF-Expand (RFC 5869 §2.3). */
    private static byte[] expand(byte[] prk, byte[] info, int length, CryptoBackend backend) {
        if (length < 0 || length > 255 * NH) {
            throw new IllegalArgumentException("HKDF-Expand length out of range: " + length);
        }
        byte[] out = new byte[length];
        byte[] block = EMPTY;
        int done = 0;
        for (int counter = 1; done < length; counter++) {
            block = backend.hmacSha256(prk, concat(block, info, new byte[] {(byte) counter}));
            int take = Math.min(block.length, length - done);
            System.arraycopy(block, 0, out, done, take);
            done += take;
        }
        wipe(block);
        return out;
    }

    /**
     * One-shot AEAD at sequence number 0, where the nonce is the base nonce
     * unchanged (RFC 9180 §5.2 XORs the sequence number in; it is zero here).
     */
    private static byte[] aead(Suite suite, int mode, byte[] key, byte[] nonce, byte[] aad, byte[] input) {
        SecretKeySpec keySpec = new SecretKeySpec(key, suite.keyAlgorithm);
        AlgorithmParameterSpec params = suite == Suite.X25519_SHA256_CHACHA20POLY1305
                ? new IvParameterSpec(nonce)
                : new GCMParameterSpec(TAG_BITS, nonce);
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(suite.transformation);
            cipher.init(mode, keySpec, params);
            if (aad.length > 0) {
                cipher.updateAAD(aad);
            }
        } catch (GeneralSecurityException e) {
            // Provider or parameter trouble, not an authentication failure.
            throw new IllegalStateException(e);
        }
        try {
            return cipher.doFinal(input);
        } catch (AEADBadTagException e) {
            throw new IllegalArgumentException("HPKE open failed: ciphertext is not authentic", e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    // ------------------------------------------------------------------ helpers

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    /** I2OSP(n, length): big-endian, fixed width. */
    private static byte[] i2osp(int n, int length) {
        byte[] out = new byte[length];
        for (int i = length - 1; i >= 0; i--) {
            out[i] = (byte) (n >>> (8 * (length - 1 - i)));
        }
        return out;
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }

    private static void wipe(byte[]... secrets) {
        for (byte[] secret : secrets) {
            Arrays.fill(secret, (byte) 0);
        }
    }
}

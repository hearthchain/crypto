package tech.hearth.crypto;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;

/**
 * The wire format for handing an API key to a recipient that published an
 * X25519 public key — typically a confidential VM (Intel TDX) that generated
 * the key inside the TD and bound it into its attestation report.
 *
 * <p>The envelope is a thin, self-describing frame around {@link Hpke}:
 *
 * <pre>
 *   offset size field
 *   0      4    "HKE1"                      format magic and version
 *   4      2    kem_id                      0x0020, DHKEM(X25519, HKDF-SHA256)
 *   6      2    kdf_id                      0x0001, HKDF-SHA256
 *   8      2    aead_id                     0x0003 by default, ChaCha20-Poly1305
 *   10     8    fingerprint                 SHA-256(recipient public key)[0..8]
 *   18     2    metadata_len
 *   20     m    metadata                    key id and expiry, see {@link Metadata}
 *   20+m   32   enc                         the encapsulated key
 *   52+m   48   ciphertext                  32-byte API key + 16-byte tag
 * </pre>
 *
 * <p>Everything before {@code enc} is passed to the AEAD as additional
 * authenticated data, so the suite ids, the recipient fingerprint and the
 * metadata are all covered by the tag: an envelope cannot be re-labelled with a
 * different key id or expiry, and the {@code info} string pins it to this
 * protocol so it cannot be replayed into another one.
 *
 * <p>The fingerprint is a routing hint, not a security control — the recipient
 * uses it to reject an envelope sealed to a previous boot's key with a clear
 * error instead of an authentication failure.
 *
 * <p><strong>What this does not give you.</strong> HPKE base mode does not
 * authenticate the sender, and an envelope stays decryptable as long as the
 * recipient's private key lives: authorize the delivery request at the
 * transport layer, keep the recipient keypair ephemeral per boot, and set
 * {@link Metadata#notAfter()}. And none of it means anything until the caller
 * has verified the attestation quote and checked that the recipient's public
 * key is the one bound into {@code REPORTDATA}.
 */
public final class ApiKeyEnvelope {
    private ApiKeyEnvelope() {}

    /** API keys are exactly this many characters. */
    public static final int API_KEY_LENGTH = 32;

    /** ChaCha20-Poly1305: no reliance on the TD having usable AES-NI. */
    public static final Hpke.Suite DEFAULT_SUITE = Hpke.Suite.X25519_SHA256_CHACHA20POLY1305;

    /** Bytes of SHA-256(public key) carried in the header. */
    public static final int FINGERPRINT_BYTES = 8;

    /** The HPKE {@code info} string. Changing it breaks compatibility, by design. */
    private static final byte[] INFO = ascii("hearth-chain/api-key-hpke/v1");

    private static final byte[] MAGIC = ascii("HKE1");
    private static final int HEADER_FIXED_BYTES = 20;
    private static final int MAX_METADATA_BYTES = 0xffff;

    private static final char[] ALPHANUMERIC =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray();
    /** Largest multiple of 62 that fits in a byte; above it, resample (no modulo bias). */
    private static final int SAMPLE_LIMIT = (256 / ALPHANUMERIC.length) * ALPHANUMERIC.length;

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * What the envelope claims about the key it carries, authenticated by the
     * AEAD tag.
     *
     * @param keyId    an identifier for the API key, 1..255 bytes of UTF-8; it
     *                 lets the recipient tell which key it received without
     *                 logging the key itself
     * @param notAfter when the key stops being valid, or {@code null} for no
     *                 expiry. Truncated to whole seconds on the wire.
     */
    public record Metadata(String keyId, Instant notAfter) {
        public Metadata {
            int length = keyId.getBytes(StandardCharsets.UTF_8).length;
            if (length < 1 || length > 255) {
                throw new IllegalArgumentException("key id must be 1..255 bytes of UTF-8, was " + length);
            }
        }

        /** Metadata with no expiry. */
        public static Metadata of(String keyId) {
            return new Metadata(keyId, null);
        }

        /** Metadata that expires at {@code notAfter}. */
        public static Metadata of(String keyId, Instant notAfter) {
            return new Metadata(keyId, notAfter);
        }

        byte[] encode() {
            byte[] id = keyId.getBytes(StandardCharsets.UTF_8);
            return ByteBuffer.allocate(1 + id.length + Long.BYTES)
                    .put((byte) id.length)
                    .put(id)
                    .putLong(notAfter == null ? 0L : notAfter.getEpochSecond())
                    .array();
        }

        static Metadata decode(byte[] encoded) {
            if (encoded.length < 1 + Long.BYTES) {
                throw new IllegalArgumentException("truncated envelope metadata");
            }
            ByteBuffer buffer = ByteBuffer.wrap(encoded);
            int length = buffer.get() & 0xff;
            if (encoded.length != 1 + length + Long.BYTES) {
                throw new IllegalArgumentException("envelope metadata length mismatch");
            }
            byte[] id = new byte[length];
            buffer.get(id);
            long epochSecond = buffer.getLong();
            return new Metadata(new String(id, StandardCharsets.UTF_8),
                    epochSecond == 0L ? null : Instant.ofEpochSecond(epochSecond));
        }
    }

    /**
     * A decrypted envelope. Call {@link #wipe()} once the key has been used —
     * the point of returning {@code char[]} is that it can be cleared, which a
     * {@code String} cannot.
     */
    public record Opened(char[] apiKey, Metadata metadata) {
        public void wipe() {
            Arrays.fill(apiKey, '\0');
        }
    }

    /** Seal an API key with the default suite and backend. */
    public static byte[] seal(byte[] recipientPublicKey, char[] apiKey, Metadata metadata) {
        return seal(recipientPublicKey, apiKey, metadata, DEFAULT_SUITE, Crypto.defaultBackend());
    }

    /**
     * Seal an API key to {@code recipientPublicKey}.
     *
     * <p>The caller must already have verified that this public key belongs to
     * the enclave it expects; this method cannot check that.
     *
     * @throws IllegalArgumentException if the API key is not {@value #API_KEY_LENGTH}
     *         alphanumeric characters
     */
    public static byte[] seal(byte[] recipientPublicKey, char[] apiKey, Metadata metadata, Hpke.Suite suite,
            CryptoBackend backend) {
        validateApiKey(apiKey);
        byte[] header = header(suite, fingerprint(recipientPublicKey, backend), metadata.encode());
        byte[] plaintext = toBytes(apiKey);
        try {
            Hpke.Sealed sealed = Hpke.seal(suite, recipientPublicKey, INFO, header, plaintext, backend);
            return ByteBuffer.allocate(header.length + sealed.enc().length + sealed.ciphertext().length)
                    .put(header)
                    .put(sealed.enc())
                    .put(sealed.ciphertext())
                    .array();
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    /** Open an envelope with the default backend, rejecting one that has expired. */
    public static Opened open(byte[] recipientSecretKey, byte[] envelope) {
        return open(recipientSecretKey, envelope, Instant.now(), Crypto.defaultBackend());
    }

    /**
     * Open an envelope.
     *
     * @param now the instant to judge {@link Metadata#notAfter()} against
     * @throws IllegalArgumentException if the envelope is malformed, sealed to a
     *         different recipient key, not authentic, or expired
     */
    public static Opened open(byte[] recipientSecretKey, byte[] envelope, Instant now, CryptoBackend backend) {
        if (envelope.length < HEADER_FIXED_BYTES) {
            throw new IllegalArgumentException("truncated envelope");
        }
        ByteBuffer buffer = ByteBuffer.wrap(envelope);
        byte[] magic = new byte[MAGIC.length];
        buffer.get(magic);
        if (!Arrays.equals(magic, MAGIC)) {
            throw new IllegalArgumentException("not an API key envelope");
        }
        int kemId = buffer.getShort() & 0xffff;
        int kdfId = buffer.getShort() & 0xffff;
        int aeadId = buffer.getShort() & 0xffff;
        if (kemId != Hpke.KEM_ID || kdfId != Hpke.KDF_ID) {
            throw new IllegalArgumentException(
                    "unsupported HPKE suite: kem=0x%04x kdf=0x%04x".formatted(kemId, kdfId));
        }
        Hpke.Suite suite = Hpke.Suite.fromAeadId(aeadId);

        byte[] fingerprint = new byte[FINGERPRINT_BYTES];
        buffer.get(fingerprint);
        int metadataLength = buffer.getShort() & 0xffff;

        int ciphertextLength = API_KEY_LENGTH + Hpke.TAG_BYTES;
        int expected = HEADER_FIXED_BYTES + metadataLength + Hpke.ENC_BYTES + ciphertextLength;
        if (envelope.length != expected) {
            throw new IllegalArgumentException(
                    "envelope length mismatch: expected %d bytes, got %d".formatted(expected, envelope.length));
        }
        byte[] metadataBytes = new byte[metadataLength];
        buffer.get(metadataBytes);
        byte[] enc = new byte[Hpke.ENC_BYTES];
        buffer.get(enc);
        byte[] ciphertext = new byte[ciphertextLength];
        buffer.get(ciphertext);

        byte[] recipientPublicKey = X25519.publicKey(recipientSecretKey);
        if (!Arrays.equals(fingerprint, fingerprint(recipientPublicKey, backend))) {
            throw new IllegalArgumentException("envelope is sealed to a different recipient key");
        }

        // Everything before enc is the AAD, so the suite ids, fingerprint and
        // metadata are all covered by the tag.
        byte[] header = Arrays.copyOf(envelope, HEADER_FIXED_BYTES + metadataLength);
        byte[] plaintext = Hpke.open(suite, recipientSecretKey, enc, INFO, header, ciphertext, backend);
        try {
            char[] apiKey = toChars(plaintext);
            try {
                validateApiKey(apiKey);
                Metadata metadata = Metadata.decode(metadataBytes);
                if (metadata.notAfter() != null && !now.isBefore(metadata.notAfter())) {
                    throw new IllegalArgumentException("envelope expired at " + metadata.notAfter());
                }
                return new Opened(apiKey, metadata);
            } catch (RuntimeException e) {
                Arrays.fill(apiKey, '\0');
                throw e;
            }
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    /** SHA-256(public key) truncated to {@value #FINGERPRINT_BYTES} bytes. */
    public static byte[] fingerprint(byte[] publicKey) {
        return fingerprint(publicKey, Crypto.defaultBackend());
    }

    /** SHA-256(public key) truncated to {@value #FINGERPRINT_BYTES} bytes. */
    public static byte[] fingerprint(byte[] publicKey, CryptoBackend backend) {
        if (publicKey.length != X25519.KEY_BYTES) {
            throw new IllegalArgumentException("public key must be " + X25519.KEY_BYTES + " bytes");
        }
        return Arrays.copyOf(backend.sha256(publicKey), FINGERPRINT_BYTES);
    }

    /**
     * A fresh {@value #API_KEY_LENGTH}-character alphanumeric API key, uniform
     * over the 62-character alphabet (rejection sampling — {@code % 62} on a
     * random byte would favour the first 8 characters).
     */
    public static char[] randomApiKey() {
        return randomApiKey(RANDOM);
    }

    /** A fresh API key from a caller-supplied source of randomness. */
    public static char[] randomApiKey(SecureRandom random) {
        char[] key = new char[API_KEY_LENGTH];
        byte[] buffer = new byte[API_KEY_LENGTH];
        for (int filled = 0; filled < API_KEY_LENGTH; ) {
            random.nextBytes(buffer);
            for (int i = 0; i < buffer.length && filled < API_KEY_LENGTH; i++) {
                int sample = buffer[i] & 0xff;
                if (sample < SAMPLE_LIMIT) {
                    key[filled++] = ALPHANUMERIC[sample % ALPHANUMERIC.length];
                }
            }
        }
        Arrays.fill(buffer, (byte) 0);
        return key;
    }

    private static byte[] header(Hpke.Suite suite, byte[] fingerprint, byte[] metadata) {
        if (metadata.length > MAX_METADATA_BYTES) {
            throw new IllegalArgumentException("envelope metadata too long: " + metadata.length);
        }
        return ByteBuffer.allocate(HEADER_FIXED_BYTES + metadata.length)
                .put(MAGIC)
                .putShort((short) Hpke.KEM_ID)
                .putShort((short) Hpke.KDF_ID)
                .putShort((short) suite.aeadId())
                .put(fingerprint)
                .putShort((short) metadata.length)
                .put(metadata)
                .array();
    }

    private static void validateApiKey(char[] apiKey) {
        if (apiKey.length != API_KEY_LENGTH) {
            throw new IllegalArgumentException("API key must be " + API_KEY_LENGTH + " characters");
        }
        for (char c : apiKey) {
            boolean alphanumeric = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
            if (!alphanumeric) {
                throw new IllegalArgumentException("API key must be alphanumeric");
            }
        }
    }

    /** ASCII only, which {@link #validateApiKey} has already established. */
    private static byte[] toBytes(char[] chars) {
        byte[] out = new byte[chars.length];
        for (int i = 0; i < chars.length; i++) {
            out[i] = (byte) chars[i];
        }
        return out;
    }

    private static char[] toChars(byte[] bytes) {
        char[] out = new char[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            out[i] = (char) (bytes[i] & 0xff);
        }
        return out;
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }
}

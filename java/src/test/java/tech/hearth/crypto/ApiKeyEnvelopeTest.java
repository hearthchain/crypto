package tech.hearth.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class ApiKeyEnvelopeTest {

    private static final Instant NOW = Instant.parse("2026-08-05T12:00:00Z");
    private static final Instant LATER = NOW.plusSeconds(3600);

    private static ApiKeyEnvelope.Metadata meta() {
        return ApiKeyEnvelope.Metadata.of("prod/ingest-api", LATER);
    }

    private static ApiKeyEnvelope.Opened open(X25519.Keypair recipient, byte[] envelope) {
        return ApiKeyEnvelope.open(recipient.secretKey(), envelope, NOW, Crypto.defaultBackend());
    }

    @ParameterizedTest
    @EnumSource(Hpke.Suite.class)
    void sealOpenRoundTrip(Hpke.Suite suite) {
        X25519.Keypair recipient = X25519.generateKeypair();
        char[] apiKey = ApiKeyEnvelope.randomApiKey();

        byte[] envelope = ApiKeyEnvelope.seal(
                recipient.publicKey(), apiKey, meta(), suite, Crypto.defaultBackend());

        // 20-byte fixed header + metadata + 32-byte enc + 32-byte key + 16-byte tag.
        int metadataLength = 1 + "prod/ingest-api".length() + Long.BYTES;
        assertEquals(20 + metadataLength + 32 + 48, envelope.length);

        ApiKeyEnvelope.Opened opened = open(recipient, envelope);
        assertArrayEquals(apiKey, opened.apiKey());
        assertEquals("prod/ingest-api", opened.metadata().keyId());
        assertEquals(LATER, opened.metadata().notAfter());

        opened.wipe();
        assertArrayEquals(new char[ApiKeyEnvelope.API_KEY_LENGTH], opened.apiKey());
    }

    @Test
    void headerCarriesTheSuiteAndRecipientFingerprint() {
        X25519.Keypair recipient = X25519.generateKeypair();
        byte[] envelope = ApiKeyEnvelope.seal(recipient.publicKey(), ApiKeyEnvelope.randomApiKey(), meta());

        assertEquals("HKE1", new String(Arrays.copyOf(envelope, 4), java.nio.charset.StandardCharsets.US_ASCII));
        assertEquals(Hpke.KEM_ID, be16(envelope, 4));
        assertEquals(Hpke.KDF_ID, be16(envelope, 6));
        assertEquals(ApiKeyEnvelope.DEFAULT_SUITE.aeadId(), be16(envelope, 8));
        assertArrayEquals(ApiKeyEnvelope.fingerprint(recipient.publicKey()),
                Arrays.copyOfRange(envelope, 10, 18));
    }

    @Test
    void rejectsEnvelopeForAnotherRecipient() {
        X25519.Keypair recipient = X25519.generateKeypair();
        X25519.Keypair other = X25519.generateKeypair();
        byte[] envelope = ApiKeyEnvelope.seal(recipient.publicKey(), ApiKeyEnvelope.randomApiKey(), meta());

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> open(other, envelope));
        assertTrue(e.getMessage().contains("different recipient key"), e.getMessage());
    }

    @Test
    void rejectsExpiredEnvelope() {
        X25519.Keypair recipient = X25519.generateKeypair();
        byte[] envelope = ApiKeyEnvelope.seal(recipient.publicKey(), ApiKeyEnvelope.randomApiKey(),
                ApiKeyEnvelope.Metadata.of("short-lived", NOW.minusSeconds(1)));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> open(recipient, envelope));
        assertTrue(e.getMessage().startsWith("envelope expired"), e.getMessage());
    }

    @Test
    void metadataWithoutExpiryNeverExpires() {
        X25519.Keypair recipient = X25519.generateKeypair();
        byte[] envelope = ApiKeyEnvelope.seal(
                recipient.publicKey(), ApiKeyEnvelope.randomApiKey(), ApiKeyEnvelope.Metadata.of("forever"));

        ApiKeyEnvelope.Opened opened = ApiKeyEnvelope.open(
                recipient.secretKey(), envelope, Instant.parse("2099-01-01T00:00:00Z"), Crypto.defaultBackend());
        assertNull(opened.metadata().notAfter());
    }

    /** Every header byte is AAD, so relabelling the metadata breaks the tag. */
    @Test
    void rejectsTamperedMetadata() {
        X25519.Keypair recipient = X25519.generateKeypair();
        byte[] envelope = ApiKeyEnvelope.seal(recipient.publicKey(), ApiKeyEnvelope.randomApiKey(),
                ApiKeyEnvelope.Metadata.of("prod/ingest-api", LATER));

        // Flip the last byte of the expiry timestamp, still inside the header.
        byte[] tampered = envelope.clone();
        int metadataEnd = 20 + 1 + "prod/ingest-api".length() + Long.BYTES;
        tampered[metadataEnd - 1] ^= 0x01;

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> open(recipient, tampered));
        assertTrue(e.getMessage().contains("not authentic"), e.getMessage());
    }

    @Test
    void rejectsTamperedCiphertextAndEncapsulatedKey() {
        X25519.Keypair recipient = X25519.generateKeypair();
        byte[] envelope = ApiKeyEnvelope.seal(recipient.publicKey(), ApiKeyEnvelope.randomApiKey(), meta());

        for (int offset : new int[] {envelope.length - 1, envelope.length - 40, envelope.length - 60}) {
            byte[] tampered = envelope.clone();
            tampered[offset] ^= 0x01;
            assertThrows(IllegalArgumentException.class, () -> open(recipient, tampered),
                    "flipping byte " + offset + " should not open");
        }
    }

    @Test
    void rejectsMalformedEnvelopes() {
        X25519.Keypair recipient = X25519.generateKeypair();
        byte[] envelope = ApiKeyEnvelope.seal(recipient.publicKey(), ApiKeyEnvelope.randomApiKey(), meta());

        assertThrows(IllegalArgumentException.class, () -> open(recipient, new byte[3]));

        byte[] wrongMagic = envelope.clone();
        wrongMagic[0] = 'X';
        assertThrows(IllegalArgumentException.class, () -> open(recipient, wrongMagic));

        byte[] truncated = Arrays.copyOf(envelope, envelope.length - 1);
        assertThrows(IllegalArgumentException.class, () -> open(recipient, truncated));

        byte[] unknownAead = envelope.clone();
        unknownAead[9] = (byte) 0xff;
        assertThrows(IllegalArgumentException.class, () -> open(recipient, unknownAead));
    }

    @Test
    void rejectsApiKeysOfTheWrongShape() {
        byte[] publicKey = X25519.generateKeypair().publicKey();
        assertThrows(IllegalArgumentException.class,
                () -> ApiKeyEnvelope.seal(publicKey, "tooshort".toCharArray(), meta()));
        assertThrows(IllegalArgumentException.class,
                () -> ApiKeyEnvelope.seal(publicKey, "0123456789012345678901234567890!".toCharArray(), meta()));
    }

    @Test
    void metadataRejectsEmptyOrOversizedKeyId() {
        assertThrows(IllegalArgumentException.class, () -> ApiKeyEnvelope.Metadata.of(""));
        assertThrows(IllegalArgumentException.class, () -> ApiKeyEnvelope.Metadata.of("k".repeat(256)));
    }

    @Test
    void randomApiKeyIsAlphanumericAndCoversTheAlphabet() {
        Set<Character> seen = new HashSet<>();
        for (int i = 0; i < 200; i++) {
            char[] key = ApiKeyEnvelope.randomApiKey();
            assertEquals(ApiKeyEnvelope.API_KEY_LENGTH, key.length);
            for (char c : key) {
                assertTrue(Character.isLetterOrDigit(c) && c < 128, "not ASCII alphanumeric: " + c);
                seen.add(c);
            }
        }
        // 6400 draws over a 62-character alphabet: every character should appear.
        assertEquals(62, seen.size());
    }

    private static int be16(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 8) | (bytes[offset + 1] & 0xff);
    }
}

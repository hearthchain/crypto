package tech.hearth.app;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;

import tech.hearth.crypto.ApiKeyEnvelope;
import tech.hearth.crypto.Crypto;
import tech.hearth.crypto.Hex;
import tech.hearth.crypto.Hpke;
import tech.hearth.crypto.X25519;

/**
 * Delivering an API key to a confidential VM: the TD publishes an X25519 public
 * key bound into its attestation report, the client seals the key to it with
 * HPKE, and only the TD can open it.
 *
 * <p>Run: {@code mvn -q compile exec:exec -DmainClass=tech.hearth.app.HpkeExample}
 */
public final class HpkeExample {
    private HpkeExample() {}

    /** What the TD must place in the 64-byte REPORTDATA field of its quote. */
    private static final byte[] REPORT_DATA_CONTEXT =
            "hearth-chain/tdx-hpke/v1".getBytes(StandardCharsets.US_ASCII);

    private static void section(String title) {
        System.out.println("\n== " + title + " ==");
    }

    public static void main(String[] args) {
        section("1) Inside the TD: generate the recipient keypair, bind it to the quote");
        // In a real TD this keypair is generated at boot and never leaves the
        // enclave; the private key is not persisted anywhere.
        X25519.Keypair enclave = X25519.generateKeypair();
        byte[] reportData = Crypto.defaultBackend()
                .sha512(concat(REPORT_DATA_CONTEXT, enclave.publicKey()));
        System.out.printf("public key (X25519, 32 B): %s%n", Hex.encode(enclave.publicKey()));
        System.out.printf("REPORTDATA  (SHA-512, 64 B): %s%n", Hex.encode(reportData));
        System.out.println("  the TD puts this in its quote; the client recomputes it from the");
        System.out.println("  public key it was handed and compares — that is the binding.");

        section("2) On the client: verify the quote, then seal the API key");
        System.out.println("(quote verification is out of scope here — check the signature chain,");
        System.out.println(" the TCB status, MRTD/RTMR, and that REPORTDATA matches the line above)");

        char[] apiKey = ApiKeyEnvelope.randomApiKey();
        ApiKeyEnvelope.Metadata metadata = ApiKeyEnvelope.Metadata.of(
                "prod/ingest-api", Instant.now().plus(24, ChronoUnit.HOURS).truncatedTo(ChronoUnit.SECONDS));
        byte[] envelope = ApiKeyEnvelope.seal(enclave.publicKey(), apiKey, metadata);

        System.out.printf("api key      : %s%n", new String(apiKey));
        System.out.printf("key id       : %s%n", metadata.keyId());
        System.out.printf("expires      : %s%n", metadata.notAfter());
        System.out.printf("suite        : %s (aead 0x%04x)%n",
                ApiKeyEnvelope.DEFAULT_SUITE, ApiKeyEnvelope.DEFAULT_SUITE.aeadId());
        System.out.printf("envelope     : %d bytes%n", envelope.length);
        System.out.printf("  %s%n", Hex.encode(envelope));

        section("3) Back inside the TD: open the envelope");
        ApiKeyEnvelope.Opened opened = ApiKeyEnvelope.open(enclave.secretKey(), envelope);
        System.out.printf("recovered    : %s%n", new String(opened.apiKey()));
        System.out.printf("key id       : %s (authenticated, not encrypted)%n", opened.metadata().keyId());
        System.out.printf("matches      : %b%n", Arrays.equals(apiKey, opened.apiKey()));
        opened.wipe();

        section("4) What an attacker gets");
        // A different TD (or a replayed public key from another machine) cannot read it.
        X25519.Keypair impostor = X25519.generateKeypair();
        System.out.printf("wrong recipient key  : %s%n", failureOf(() -> ApiKeyEnvelope.open(impostor.secretKey(), envelope)));

        // The metadata is authenticated, so it cannot be relabelled in flight:
        // flip the last byte of the expiry timestamp, still inside the header.
        byte[] relabelled = envelope.clone();
        int metadataEnd = 20 + (((envelope[18] & 0xff) << 8) | (envelope[19] & 0xff));
        relabelled[metadataEnd - 1] ^= 0x01;
        System.out.printf("relabelled expiry    : %s%n", failureOf(() -> ApiKeyEnvelope.open(enclave.secretKey(), relabelled)));

        // And so is the ciphertext.
        byte[] tampered = envelope.clone();
        tampered[tampered.length - 1] ^= 0x01;
        System.out.printf("flipped tag byte     : %s%n", failureOf(() -> ApiKeyEnvelope.open(enclave.secretKey(), tampered)));

        // An expired envelope is rejected even though it decrypts correctly.
        byte[] stale = ApiKeyEnvelope.seal(enclave.publicKey(), ApiKeyEnvelope.randomApiKey(),
                ApiKeyEnvelope.Metadata.of("prod/ingest-api", Instant.now().minusSeconds(1)));
        System.out.printf("expired envelope     : %s%n", failureOf(() -> ApiKeyEnvelope.open(enclave.secretKey(), stale)));

        section("5) The raw HPKE layer");
        byte[] info = "hearth-chain/example/v1".getBytes(StandardCharsets.UTF_8);
        Hpke.Sealed sealed = Hpke.seal(Hpke.Suite.X25519_SHA256_CHACHA20POLY1305,
                enclave.publicKey(), info, new byte[0], "any payload".getBytes(StandardCharsets.UTF_8));
        System.out.printf("enc (32 B)   : %s%n", Hex.encode(sealed.enc()));
        System.out.printf("ciphertext   : %s%n", Hex.encode(sealed.ciphertext()));
        System.out.printf("opened       : %s%n", new String(Hpke.open(
                Hpke.Suite.X25519_SHA256_CHACHA20POLY1305, enclave.secretKey(),
                sealed.enc(), info, new byte[0], sealed.ciphertext()), StandardCharsets.UTF_8));
        System.out.println();
    }

    private static String failureOf(Runnable action) {
        try {
            action.run();
            return "OPENED — this should not happen";
        } catch (RuntimeException e) {
            return "rejected: " + e.getMessage();
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}

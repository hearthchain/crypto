package tech.hearth.app;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;

import tech.hearth.crypto.ApiKeyEnvelope;
import tech.hearth.crypto.Hex;
import tech.hearth.crypto.Hpke;
import tech.hearth.crypto.SigningKey;
import tech.hearth.crypto.X25519;

/**
 * Delivering an API key to a confidential VM: the TD's enclave identity is an
 * Ed25519 key (the same key node-jvm's StartBoostTransaction registers on
 * chain, see RegisteredEnclave/BindApiKeyTransaction), the client converts its
 * public half to X25519 and seals the key to it with HPKE, and only the TD
 * (holding the matching Ed25519 seed) can open it.
 *
 * <p>Run: {@code mvn -q compile exec:exec -DmainClass=tech.hearth.app.HpkeExample}
 */
public final class HpkeExample {
    private HpkeExample() {}

    private static final SecureRandom RANDOM = new SecureRandom();

    private static void section(String title) {
        System.out.println("\n== " + title + " ==");
    }

    public static void main(String[] args) {
        section("1) Inside the TD: generate the enclave identity, bind it into the quote");
        // In a real TD this key is generated at boot and never leaves the enclave;
        // the seed is not persisted anywhere. It is an Ed25519 identity, not a
        // native X25519 keypair - report_data[32:64] carries the raw Ed25519
        // public key, and that is also the exact 32 bytes BindApiKeyTransaction's
        // enclavePublicKey field and the on-chain RegisteredEnclave record use.
        byte[] seed = new byte[32];
        RANDOM.nextBytes(seed);
        SigningKey enclaveIdentity = SigningKey.fromSeed(seed);
        byte[] enclavePublicKey = enclaveIdentity.publicKey();

        // report_data = blockId(32) || enclavePublicKey(32), raw concatenation, no
        // hashing - this is exactly what StartBoostTransactionDiff.extractEnclaveKey/
        // verifyFreshness on chain expect. blockId would be a real, recent block id
        // in production (checked against a freshness window); here it just stands in
        // for one.
        byte[] blockId = new byte[32];
        RANDOM.nextBytes(blockId);
        byte[] reportData = concat(blockId, enclavePublicKey);

        System.out.printf("enclave public key (Ed25519, 32 B): %s%n", Hex.encode(enclavePublicKey));
        System.out.printf("report_data          (64 B): %s%n", Hex.encode(reportData));
        System.out.println("  the TD's quote carries this report_data; the on-chain StartBoostTransaction");
        System.out.println("  registers report_data[32:64] verbatim as RegisteredEnclave.enclavePublicKey.");

        section("2) The TD's enclave key becomes registered on chain");
        System.out.println("(StartBoostTransaction verification is out of scope here - see node-jvm's");
        System.out.println(" StartBoostTransactionDiff for the quote signature chain and freshness check)");
        System.out.printf("this is what a BindApiKeyTransaction's enclavePublicKey field must equal: %s%n",
                Hex.encode(enclavePublicKey));

        section("3) On the client: starting from just that 32-byte Ed25519 key, seal an API key");
        // The client never sees the enclave's seed - only the 32-byte Ed25519
        // public key, either straight out of the quote or read back from the
        // RegisteredEnclave registry after StartBoost lands. Converting only the
        // public half is exactly what X25519.fromEd25519PublicKey is for.
        byte[] recipientPublicKey = X25519.fromEd25519PublicKey(enclavePublicKey);

        char[] apiKey = ApiKeyEnvelope.randomApiKey();
        ApiKeyEnvelope.Metadata metadata = ApiKeyEnvelope.Metadata.of(
                "prod/ingest-api", Instant.now().plus(24, ChronoUnit.HOURS).truncatedTo(ChronoUnit.SECONDS));
        byte[] envelope = ApiKeyEnvelope.seal(recipientPublicKey, apiKey, metadata);

        System.out.printf("api key      : %s%n", new String(apiKey));
        System.out.printf("key id       : %s%n", metadata.keyId());
        System.out.printf("expires      : %s%n", metadata.notAfter());
        System.out.printf("suite        : %s (aead 0x%04x)%n",
                ApiKeyEnvelope.DEFAULT_SUITE, ApiKeyEnvelope.DEFAULT_SUITE.aeadId());
        System.out.printf("envelope     : %d bytes%n", envelope.length);
        System.out.printf("  %s%n", Hex.encode(envelope));

        section("4) Ready to broadcast: BindApiKeyTransaction's two fields");
        System.out.println("  {");
        System.out.printf("    \"type\": 9,%n"); // TransactionType.BindApiKey (node-jvm)
        System.out.printf("    \"enclavePublicKey\": \"%s\",%n", Hex.encode(enclavePublicKey));
        System.out.printf("    \"encryptedApiKey\": \"%s\"%n", Hex.encode(envelope));
        System.out.println("  }");
        System.out.println("  (senderPublicKey/fee/proofs omitted - see api/http/requests/BindApiKeyRequest)");

        section("5) Back inside the TD: open the envelope");
        // The enclave still holds the seed, so it derives the X25519 secret key
        // itself via SigningKey.toX25519() - the client-side conversion above only
        // ever needed the public half.
        ApiKeyEnvelope.Opened opened = ApiKeyEnvelope.open(enclaveIdentity.toX25519().secretKey(), envelope);
        System.out.printf("recovered    : %s%n", new String(opened.apiKey()));
        System.out.printf("key id       : %s (authenticated, not encrypted)%n", opened.metadata().keyId());
        System.out.printf("matches      : %b%n", Arrays.equals(apiKey, opened.apiKey()));
        opened.wipe();

        section("6) What an attacker gets");
        // A different TD (or a replayed public key from another machine) cannot read it.
        byte[] impostorSeed = new byte[32];
        RANDOM.nextBytes(impostorSeed);
        SigningKey impostor = SigningKey.fromSeed(impostorSeed);
        System.out.printf("wrong recipient key  : %s%n",
                failureOf(() -> ApiKeyEnvelope.open(impostor.toX25519().secretKey(), envelope)));

        // The metadata is authenticated, so it cannot be relabelled in flight:
        // flip the last byte of the expiry timestamp, still inside the header.
        byte[] relabelled = envelope.clone();
        int metadataEnd = 20 + (((envelope[18] & 0xff) << 8) | (envelope[19] & 0xff));
        relabelled[metadataEnd - 1] ^= 0x01;
        System.out.printf("relabelled expiry    : %s%n",
                failureOf(() -> ApiKeyEnvelope.open(enclaveIdentity.toX25519().secretKey(), relabelled)));

        // And so is the ciphertext.
        byte[] tampered = envelope.clone();
        tampered[tampered.length - 1] ^= 0x01;
        System.out.printf("flipped tag byte     : %s%n",
                failureOf(() -> ApiKeyEnvelope.open(enclaveIdentity.toX25519().secretKey(), tampered)));

        // An expired envelope is rejected even though it decrypts correctly.
        byte[] stale = ApiKeyEnvelope.seal(recipientPublicKey, ApiKeyEnvelope.randomApiKey(),
                ApiKeyEnvelope.Metadata.of("prod/ingest-api", Instant.now().minusSeconds(1)));
        System.out.printf("expired envelope     : %s%n",
                failureOf(() -> ApiKeyEnvelope.open(enclaveIdentity.toX25519().secretKey(), stale)));

        section("7) The raw HPKE layer - interop with the Go miner's fixed vectors");
        // The miner's integration test (internal/enclave/integration_vectors_test.go)
        // derives a demo TD identity from a fixed ed25519 seed and reuses it,
        // X25519-converted via SigningKey.toX25519(), as the HPKE recipient key -
        // the same enclave-identity-to-recipient-key pattern used above, just with
        // fixed inputs. Reproducing its constants here proves this library's raw
        // HPKE layer is wire-compatible with cloudflare/circl's.
        byte[] minerSeed = "hearth-integration-demo-seed-001".getBytes(StandardCharsets.US_ASCII);
        SigningKey minerIdentity = SigningKey.fromSeed(minerSeed);
        byte[] minerMessage =
                "hearth demo settlement v0: epoch 42, client 0x0102030405060708, spent 123456"
                        .getBytes(StandardCharsets.UTF_8);
        String expectedSignature = "1fb7407c5eafd14abd3cd256b319d6d314d1f09db7ef22b3d46d85ae821d7b03"
                + "78b2b0b6fe2b19c6f5ac923a9af4b757e1e347ff1b327089965c6bab17c9770b";
        System.out.printf("ed25519 signature matches the miner vector : %b%n",
                Hex.encode(minerIdentity.sign(minerMessage)).equals(expectedSignature));

        X25519.Keypair minerRecipient = minerIdentity.toX25519();
        byte[] info = "hearth-api-key-envelope-v0".getBytes(StandardCharsets.UTF_8);
        String minerApiKey = "sk-hearth-demo-4f3b45b412ebaad3";
        byte[] minerEnvelope = Hex.decode(
                "8f779588d219fb25de2ad323732d301756721878a6deefbc05c6f80d660e5f62"
                        + "2af1a82c6381cf4e2d9f1cc3b9c3899cc5aa99c8aa93cd1d394217d3d3e95ec80475d8059968963e800b0fd4f66864");
        byte[] minerEnc = Arrays.copyOfRange(minerEnvelope, 0, Hpke.ENC_BYTES);
        byte[] minerCiphertext = Arrays.copyOfRange(minerEnvelope, Hpke.ENC_BYTES, minerEnvelope.length);
        byte[] decryptedMinerEnvelope = Hpke.open(Hpke.Suite.X25519_SHA256_CHACHA20POLY1305,
                minerRecipient.secretKey(), minerEnc, info, new byte[0], minerCiphertext);
        System.out.printf("decrypts the miner's fixed envelope        : %s (expected %s)%n",
                new String(decryptedMinerEnvelope, StandardCharsets.UTF_8), minerApiKey);

        Hpke.Sealed sealed = Hpke.seal(Hpke.Suite.X25519_SHA256_CHACHA20POLY1305,
                minerRecipient.publicKey(), info, new byte[0], minerApiKey.getBytes(StandardCharsets.UTF_8));
        System.out.printf("enc (32 B)   : %s%n", Hex.encode(sealed.enc()));
        System.out.printf("ciphertext   : %s%n", Hex.encode(sealed.ciphertext()));
        System.out.printf("opened       : %s%n", new String(Hpke.open(
                Hpke.Suite.X25519_SHA256_CHACHA20POLY1305, minerRecipient.secretKey(),
                sealed.enc(), info, new byte[0], sealed.ciphertext()), StandardCharsets.UTF_8));
        System.out.println();
    }

    private static String failureOf(Runnable action) {
        try {
            action.run();
            return "OPENED - this should not happen";
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

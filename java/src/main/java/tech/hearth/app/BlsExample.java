package tech.hearth.app;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import tech.hearth.crypto.Bip39;
import tech.hearth.crypto.BlsKey;
import tech.hearth.crypto.Hex;
import tech.hearth.crypto.KeyTree;

/**
 * BLS12-381 finality example: derive several validators' BLS keys from one
 * mnemonic (EIP-2333), have each sign the same finality vote, aggregate the
 * signatures, and verify the aggregate against the aggregate of the public keys
 * with a single pairing check (the stake-weighted finality path).
 *
 * <p>Run: {@code mvn -q compile exec:java -Dexec.mainClass=tech.hearth.app.BlsExample}
 */
public final class BlsExample {
    private BlsExample() {}

    private static final String MNEMONIC =
            "abandon abandon abandon abandon abandon abandon abandon abandon "
                    + "abandon abandon abandon about";
    private static final int VALIDATORS = 3;

    private static void section(String title) {
        System.out.println("\n== " + title + " ==");
    }

    public static void main(String[] args) {
        byte[] seed = Bip39.toSeed(MNEMONIC);
        byte[] voteMessage = "finalize block 42".getBytes(StandardCharsets.UTF_8);

        section("1) Derive BLS finality keys (EIP-2333) + proof of possession");
        List<BlsKey> validators = new ArrayList<>();
        List<byte[]> pubkeys = new ArrayList<>();
        for (int i = 0; i < VALIDATORS; i++) {
            BlsKey key = BlsKey.fromSeed(seed, i);
            validators.add(key);
            pubkeys.add(key.publicKey());
            byte[] pop = key.proofOfPossession();
            System.out.printf("validator %d  (%s)%n", i, KeyTree.blsPath(i));
            System.out.printf("  pubkey (G1, %2d B): %s%n", key.publicKey().length, Hex.encode(key.publicKey()));
            System.out.printf("  PoP valid        : %b%n", BlsKey.verifyProofOfPossession(key.publicKey(), pop));
        }

        section("2) Each validator signs the same finality vote");
        List<byte[]> signatures = new ArrayList<>();
        for (int i = 0; i < VALIDATORS; i++) {
            byte[] sig = validators.get(i).sign(voteMessage);
            signatures.add(sig);
            System.out.printf("validator %d  sig (G2, %2d B): %s%n", i, sig.length, Hex.encode(sig));
        }

        section("3) Aggregate + verify (one pairing check for all signers)");
        byte[] aggregateSig = BlsKey.aggregate(signatures);
        byte[] aggregatePk = BlsKey.aggregatePublicKeys(pubkeys);
        System.out.println("message           : " + new String(voteMessage, StandardCharsets.UTF_8));
        System.out.println("aggregate sig     : " + Hex.encode(aggregateSig) + "  (still 96 bytes)");
        System.out.println("aggregate pubkey  : " + Hex.encode(aggregatePk));
        System.out.println("verify (all signed): "
                + (BlsKey.fastAggregateVerify(pubkeys, voteMessage, aggregateSig) ? "VALID" : "INVALID"));
        System.out.println("tampered message   : "
                + (BlsKey.fastAggregateVerify(pubkeys, "finalize block 43".getBytes(StandardCharsets.UTF_8), aggregateSig)
                        ? "VALID (!)" : "INVALID (expected)"));
        System.out.println("missing one signer : "
                + (BlsKey.fastAggregateVerify(pubkeys.subList(0, VALIDATORS - 1), voteMessage, aggregateSig)
                        ? "VALID (!)" : "INVALID (expected)"));
    }
}

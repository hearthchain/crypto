package tech.hearth.crypto;

import java.util.List;

import supranational.blst.BLST_ERROR;
import supranational.blst.P1;
import supranational.blst.P1_Affine;
import supranational.blst.P2;
import supranational.blst.P2_Affine;
import supranational.blst.Pairing;
import supranational.blst.SecretKey;

/**
 * A BLS12-381 finality key: signing plus signature/public-key aggregation, on
 * blst. Defaults to the eth2 ciphersuite <b>minimal-pubkey-size,
 * proof-of-possession</b> — public keys are 48-byte G1 points, signatures are
 * 96-byte G2 points. A second, <b>Basic</b> ciphersuite ({@link #signBasic},
 * {@link #verifyBasic}, {@link #fastAggregateVerifyBasic}) is also available
 * for callers that enforce rogue-key defense themselves out of band (e.g. a
 * proof of possession bound to something beyond the bare public key, such as
 * a validity period) instead of relying on the POP ciphersuite's dedicated
 * proof-of-possession DST; the two ciphersuites use disjoint DSTs, so a
 * signature under one is never mistakable for the other.
 *
 * <p>The secret scalar is the one derived by {@link KeyTree#blsSecretKey} /
 * {@link Bls} (EIP-2333); it is loaded verbatim via {@code from_bendian} (not
 * re-derived), so a key here matches the derivation the other implementations
 * agree on. The scalar never leaves this object — only {@link #publicKey()},
 * {@link #sign}, {@link #signBasic} and {@link #proofOfPossession()} are
 * exposed.
 */
public final class BlsKey {

    /** Ciphersuite DST for signatures (min-pubkey-size, RO, proof-of-possession). */
    private static final String DST_SIG = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    /** Ciphersuite DST for proofs of possession. */
    private static final String DST_POP = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    /** Ciphersuite DST for the Basic (unaugmented) scheme: no built-in rogue-key defense. */
    private static final String DST_SIG_BASIC = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    /** KeyGen (draft-irtf-cfrg-bls-signature, the algorithm blst calls {@code keygen_v5}) salt. */
    private static final byte[] KEYGEN_SALT = "BLS-SIG-KEYGEN-SALT-".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    public static final int PUBLIC_KEY_BYTES = 48;
    public static final int SIGNATURE_BYTES = 96;

    private final SecretKey sk;
    private final byte[] publicKey;

    private BlsKey(SecretKey sk, byte[] publicKey) {
        this.sk = sk;
        this.publicKey = publicKey;
    }

    /** Load a BLS key from a 32-byte big-endian secret scalar (e.g. {@link KeyTree#blsSecretKey}). */
    public static BlsKey fromSecretKey(byte[] secretKey) {
        if (secretKey.length != 32) {
            throw new IllegalArgumentException("BLS secret key must be 32 bytes");
        }
        SecretKey sk = new SecretKey();
        sk.from_bendian(secretKey); // import the derived scalar as-is; do NOT re-run keygen
        return new BlsKey(sk, new P1(sk).compress());
    }

    /** Derive the BLS finality key for an account (EIP-2333) from a BIP-39 seed. */
    public static BlsKey fromSeed(byte[] seed, int account) {
        return fromSecretKey(KeyTree.blsSecretKey(seed, account));
    }

    /**
     * Derive a key straight from an arbitrary-length seed via blst's own KeyGen
     * (draft-irtf-cfrg-bls-signature {@code keygen_v5}), not EIP-2333. Unlike
     * {@link #fromSeed}, this takes no account index and accepts any seed length
     * (a seed shorter than 32 bytes may collapse to the zero scalar, which is a
     * valid, if degenerate, key). Intended for tests/tooling that just need a
     * deterministic key from arbitrary bytes, not real account derivation.
     */
    public static BlsKey fromSeedKeygenV5(byte[] seed) {
        SecretKey sk = new SecretKey();
        sk.keygen_v5(seed, KEYGEN_SALT);
        return new BlsKey(sk, new P1(sk).compress());
    }

    /** The 48-byte compressed G1 public key. */
    public byte[] publicKey() {
        return publicKey.clone();
    }

    /** Sign {@code message}, returning the 96-byte compressed G2 signature. */
    public byte[] sign(byte[] message) {
        return new P2().hash_to(message, DST_SIG).sign_with(sk).compress();
    }

    /** Sign {@code message} under the Basic ciphersuite (see the class doc). */
    public byte[] signBasic(byte[] message) {
        return new P2().hash_to(message, DST_SIG_BASIC).sign_with(sk).compress();
    }

    /** A proof of possession: a signature over this key's own public key (distinct DST). */
    public byte[] proofOfPossession() {
        return new P2().hash_to(publicKey, DST_POP).sign_with(sk).compress();
    }

    // --- verification / aggregation (operate on public keys + signatures) --------

    /** Verify a single signature. */
    public static boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
        return coreVerify(publicKey, message, signature, DST_SIG);
    }

    /** Verify a single signature under the Basic ciphersuite (see the class doc). */
    public static boolean verifyBasic(byte[] publicKey, byte[] message, byte[] signature) {
        return coreVerify(publicKey, message, signature, DST_SIG_BASIC);
    }

    /** Verify a proof of possession against a public key. */
    public static boolean verifyProofOfPossession(byte[] publicKey, byte[] pop) {
        return coreVerify(publicKey, publicKey, pop, DST_POP);
    }

    /**
     * Whether {@code publicKey} decodes to a valid, non-identity point in the correct
     * subgroup. Intended for a one-time check when registering a new signer's key,
     * ahead of ever using it in {@link #fastAggregateVerifyBasic}/{@link #fastAggregateVerify}.
     */
    public static boolean isValidPublicKey(byte[] publicKey) {
        try {
            P1_Affine pk = new P1_Affine(publicKey);
            return pk.in_group() && !pk.is_inf();
        } catch (RuntimeException e) {
            return false; // malformed point encoding, etc.
        }
    }

    /** Aggregate signatures into one 96-byte signature (point addition in G2). */
    public static byte[] aggregate(List<byte[]> signatures) {
        if (signatures.isEmpty()) {
            throw new IllegalArgumentException("no signatures to aggregate");
        }
        P2 agg = new P2(signatures.get(0));
        for (int i = 1; i < signatures.size(); i++) {
            agg.aggregate(new P2_Affine(signatures.get(i)));
        }
        return agg.compress();
    }

    /** Aggregate public keys into one 48-byte key (for same-message fast verification). */
    public static byte[] aggregatePublicKeys(List<byte[]> publicKeys) {
        if (publicKeys.isEmpty()) {
            throw new IllegalArgumentException("no public keys to aggregate");
        }
        P1 agg = new P1(publicKeys.get(0));
        for (int i = 1; i < publicKeys.size(); i++) {
            agg.aggregate(new P1_Affine(publicKeys.get(i)));
        }
        return agg.compress();
    }

    /**
     * Fast aggregate verify: every signer signed the <b>same</b> {@code message}.
     * One pairing check against the aggregate of their public keys — the finality
     * path. Safe only under proof-of-possession (verify each signer's PoP at
     * registration to defeat rogue-key attacks).
     */
    public static boolean fastAggregateVerify(List<byte[]> publicKeys, byte[] message, byte[] aggregateSignature) {
        return verify(aggregatePublicKeys(publicKeys), message, aggregateSignature);
    }

    /** {@link #fastAggregateVerify}, under the Basic ciphersuite (see the class doc). */
    public static boolean fastAggregateVerifyBasic(List<byte[]> publicKeys, byte[] message, byte[] aggregateSignature) {
        return verifyBasic(aggregatePublicKeys(publicKeys), message, aggregateSignature);
    }

    private static boolean coreVerify(byte[] publicKey, byte[] message, byte[] signature, String dst) {
        try {
            P1_Affine pk = new P1_Affine(publicKey);
            P2_Affine sig = new P2_Affine(signature);
            if (!pk.in_group() || !sig.in_group()) {
                return false;
            }
            Pairing ctx = new Pairing(true, dst); // hash-to-curve (RO), min-pubkey-size
            if (ctx.aggregate(pk, sig, message) != BLST_ERROR.BLST_SUCCESS) {
                return false;
            }
            ctx.commit();
            return ctx.finalverify();
        } catch (RuntimeException e) {
            return false; // malformed point encoding, etc.
        }
    }
}

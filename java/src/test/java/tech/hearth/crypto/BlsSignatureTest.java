package tech.hearth.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;

class BlsSignatureTest {

    /** A deterministic non-mnemonic test seed (see the earlier discussion). */
    private static byte[] seed(String label) {
        return Crypto.defaultBackend().sha512(("hearth-test:" + label).getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void loadsExactEip2333Scalar() {
        // fromSecretKey imports the scalar verbatim (from_bendian), not re-derived,
        // so it matches deriving straight from the KeyTree scalar.
        byte[] sk = KeyTree.blsSecretKey(seed("acct"), 0);
        assertArrayEquals(BlsKey.fromSecretKey(sk).publicKey(), BlsKey.fromSeed(seed("acct"), 0).publicKey());
    }

    @Test
    void signVerifyAndProofOfPossession() {
        BlsKey key = BlsKey.fromSeed(seed("validator-0"), 0);
        assertEquals(BlsKey.PUBLIC_KEY_BYTES, key.publicKey().length);

        byte[] message = utf8("finalize block 42");
        byte[] signature = key.sign(message);
        assertEquals(BlsKey.SIGNATURE_BYTES, signature.length);

        assertTrue(BlsKey.verify(key.publicKey(), message, signature));
        assertFalse(BlsKey.verify(key.publicKey(), utf8("finalize block 43"), signature));

        byte[] pop = key.proofOfPossession();
        assertTrue(BlsKey.verifyProofOfPossession(key.publicKey(), pop));
        // a normal signature is not a valid PoP (different DST + message).
        assertFalse(BlsKey.verifyProofOfPossession(key.publicKey(), signature));
    }

    @Test
    void aggregateSameMessageFinalityVote() {
        byte[] message = utf8("finalize block 42");
        List<BlsKey> validators = List.of(
                BlsKey.fromSeed(seed("v0"), 0),
                BlsKey.fromSeed(seed("v1"), 0),
                BlsKey.fromSeed(seed("v2"), 0));

        List<byte[]> pubkeys = validators.stream().map(BlsKey::publicKey).toList();
        List<byte[]> signatures = validators.stream().map(v -> v.sign(message)).toList();

        byte[] aggregate = BlsKey.aggregate(signatures);
        assertEquals(BlsKey.SIGNATURE_BYTES, aggregate.length);

        assertTrue(BlsKey.fastAggregateVerify(pubkeys, message, aggregate));
        // wrong message rejected
        assertFalse(BlsKey.fastAggregateVerify(pubkeys, utf8("finalize block 99"), aggregate));
        // a missing signer's key rejected (the aggregate signature still includes them)
        assertFalse(BlsKey.fastAggregateVerify(pubkeys.subList(0, 2), message, aggregate));
    }
}

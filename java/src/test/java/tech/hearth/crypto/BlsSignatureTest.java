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

    @Test
    void basicCiphersuiteIsDisjointFromPop() {
        BlsKey key = BlsKey.fromSeed(seed("validator-basic"), 0);
        byte[] message = utf8("commit period 7");

        byte[] basicSig = key.signBasic(message);
        assertTrue(BlsKey.verifyBasic(key.publicKey(), message, basicSig));
        assertFalse(BlsKey.verifyBasic(key.publicKey(), utf8("commit period 8"), basicSig));

        // a Basic-ciphersuite signature is not a valid POP-ciphersuite signature over the same message, or vice versa.
        assertFalse(BlsKey.verify(key.publicKey(), message, basicSig));
        assertFalse(BlsKey.verifyBasic(key.publicKey(), message, key.sign(message)));
    }

    @Test
    void fastAggregateVerifyBasicMatchesFastAggregateVerify() {
        byte[] message = utf8("commit period 7");
        List<BlsKey> validators = List.of(
                BlsKey.fromSeed(seed("basic-v0"), 0),
                BlsKey.fromSeed(seed("basic-v1"), 0),
                BlsKey.fromSeed(seed("basic-v2"), 0));

        List<byte[]> pubkeys = validators.stream().map(BlsKey::publicKey).toList();
        List<byte[]> signatures = validators.stream().map(v -> v.signBasic(message)).toList();
        byte[] aggregate = BlsKey.aggregate(signatures);

        assertTrue(BlsKey.fastAggregateVerifyBasic(pubkeys, message, aggregate));
        assertFalse(BlsKey.fastAggregateVerifyBasic(pubkeys, utf8("commit period 8"), aggregate));
        assertFalse(BlsKey.fastAggregateVerifyBasic(pubkeys.subList(0, 2), message, aggregate));
    }

    @Test
    void isValidPublicKeyRejectsMalformedAndInfinity() {
        BlsKey key = BlsKey.fromSeed(seed("validator-valid"), 0);
        assertTrue(BlsKey.isValidPublicKey(key.publicKey()));

        assertFalse(BlsKey.isValidPublicKey(new byte[BlsKey.PUBLIC_KEY_BYTES])); // all-zero: not a valid compressed point
        assertFalse(BlsKey.isValidPublicKey(new byte[]{1, 2, 3})); // wrong length

        // a seed shorter than 32 bytes collapses to the zero scalar (see fromSeedKeygenV5), whose
        // public key is the point at infinity: well-formed, but rejected as unusable for signing.
        byte[] zeroKeyPublicKey = BlsKey.fromSeedKeygenV5(new byte[]{1, 2, 3}).publicKey();
        assertFalse(BlsKey.isValidPublicKey(zeroKeyPublicKey));
    }

    @Test
    void fromSeedKeygenV5IsDeterministicAndAcceptsShortSeeds() {
        BlsKey a = BlsKey.fromSeedKeygenV5(utf8("-EXACTLY-32-BYTES-LENGTH-STRING-"));
        BlsKey b = BlsKey.fromSeedKeygenV5(utf8("-EXACTLY-32-BYTES-LENGTH-STRING-"));
        assertArrayEquals(a.publicKey(), b.publicKey());

        // shorter-than-32-byte seeds are accepted (unlike EIP-2333's fromSeed), not rejected.
        BlsKey short1 = BlsKey.fromSeedKeygenV5(new byte[]{1, 2, 3});
        BlsKey short2 = BlsKey.fromSeedKeygenV5(new byte[]{1, 2, 3});
        assertArrayEquals(short1.publicKey(), short2.publicKey());
    }
}

package tech.hearth.crypto;

import java.util.Arrays;

/**
 * Ed25519 (EdDSA, RFC 8032) signature verification and shared helpers. The
 * secret-holding key types live in {@link SigningKey} and {@link VrfKey}; this
 * class only verifies signatures (by public key) and exposes the RFC 8032 scalar
 * derivation that the ECVRF shares.
 */
public final class Ed25519 {
    private Ed25519() {}

    /** Verify a detached signature using the default backend. */
    public static boolean verify(byte[] signature, byte[] message, byte[] publicKey) {
        return verify(signature, message, publicKey, Crypto.defaultBackend());
    }

    public static boolean verify(byte[] signature, byte[] message, byte[] publicKey, CryptoBackend backend) {
        return backend.verifyDetached(signature, message, publicKey);
    }

    /** RFC 8032 secret scalar: clamp(SHA-512(seed)[0..32]). Used by ECVRF. */
    static byte[] secretScalar(byte[] seed, CryptoBackend backend) {
        byte[] a = Arrays.copyOfRange(backend.sha512(seed), 0, 32);
        a[0] &= 0xF8;
        a[31] = (byte) ((a[31] & 0x7F) | 0x40);
        return a;
    }

    /** RFC 8032 nonce prefix: SHA-512(seed)[32..64]. Used by ECVRF nonce gen. */
    static byte[] noncePrefix(byte[] seed, CryptoBackend backend) {
        return Arrays.copyOfRange(backend.sha512(seed), 32, 64);
    }
}

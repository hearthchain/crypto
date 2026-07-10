package tech.hearth.crypto;

import java.util.Arrays;

/**
 * Ed25519 (EdDSA, RFC 8032) keys and signatures — the standard, Ledger-native
 * signature scheme. The same key material also backs the ECVRF (see {@link Ecvrf}).
 */
public final class Ed25519 {
    private Ed25519() {}

    /**
     * An Ed25519 keypair derived from a 32-byte seed.
     *
     * @param seed      the 32-byte SLIP-0010 node key (the RFC 9381 "SK")
     * @param publicKey 32-byte compressed point Y = x*B
     * @param secretKey the 64-byte expanded form (seed || publicKey)
     */
    public record KeyPair(byte[] seed, byte[] publicKey, byte[] secretKey) {
        /** Sign using the default backend. */
        public byte[] sign(byte[] message) {
            return sign(message, Crypto.defaultBackend());
        }

        public byte[] sign(byte[] message, CryptoBackend backend) {
            return backend.signDetached(message, secretKey);
        }
    }

    /** Keypair from a 32-byte seed using the default backend. */
    public static KeyPair fromSeed(byte[] seed) {
        return fromSeed(seed, Crypto.defaultBackend());
    }

    /** Verify using the default backend. */
    public static boolean verify(byte[] signature, byte[] message, byte[] publicKey) {
        return verify(signature, message, publicKey, Crypto.defaultBackend());
    }

    public static KeyPair fromSeed(byte[] seed, CryptoBackend backend) {
        if (seed.length != 32) {
            throw new IllegalArgumentException("Ed25519 seed must be 32 bytes");
        }
        CryptoBackend.RawKeypair raw = backend.signSeedKeypair(seed);
        return new KeyPair(seed.clone(), raw.publicKey(), raw.secretKey());
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

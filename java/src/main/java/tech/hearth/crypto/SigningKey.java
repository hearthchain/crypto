package tech.hearth.crypto;

/**
 * An Ed25519 key used to <em>sign</em> (transactions, blocks, consensus messages).
 *
 * <p>It is a distinct type from {@link VrfKey} on purpose: the two roles must
 * never share a key, because EdDSA and ECVRF over the same scalar enable a
 * cross-protocol nonce-collision key-recovery attack. Keeping them as separate
 * types makes that mistake a compile error rather than a convention.
 *
 * <p>Only {@link #publicKey()} and {@link #sign} are exposed; the secret material
 * never leaves this object.
 */
public final class SigningKey {

    private final byte[] seed;      // 32-byte SLIP-0010 node key
    private final byte[] publicKey; // 32-byte compressed point
    private final byte[] secretKey; // 64-byte expanded form (seed || publicKey)

    private SigningKey(byte[] seed, byte[] publicKey, byte[] secretKey) {
        this.seed = seed;
        this.publicKey = publicKey;
        this.secretKey = secretKey;
    }

    /** Derive a signing key from a 32-byte seed using the default backend. */
    public static SigningKey fromSeed(byte[] seed) {
        return fromSeed(seed, Crypto.defaultBackend());
    }

    public static SigningKey fromSeed(byte[] seed, CryptoBackend backend) {
        if (seed.length != 32) {
            throw new IllegalArgumentException("Ed25519 seed must be 32 bytes");
        }
        CryptoBackend.RawKeypair raw = backend.signSeedKeypair(seed);
        return new SigningKey(seed.clone(), raw.publicKey(), raw.secretKey());
    }

    /** The 32-byte Ed25519 public key. */
    public byte[] publicKey() {
        return publicKey.clone();
    }

    /**
     * This key's (network-independent) account address. Render it with
     * {@link Address#toBech32(String)} or {@link Address#toBech32()}.
     */
    public Address toAddress() {
        return Address.fromPublicKey(publicKey);
    }

    /** Produce a detached Ed25519 signature over {@code message} (default backend). */
    public byte[] sign(byte[] message) {
        return sign(message, Crypto.defaultBackend());
    }

    public byte[] sign(byte[] message, CryptoBackend backend) {
        return backend.signDetached(message, secretKey);
    }
}

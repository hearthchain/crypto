package tech.hearth.crypto;

/**
 * An Ed25519 key used <em>only</em> to produce ECVRF proofs (RFC 9381).
 *
 * <p>Deliberately distinct from {@link SigningKey}: it exposes no EdDSA
 * {@code sign} method, and its raw seed never leaves this package. The only way
 * to use it is {@link Ecvrf#prove(VrfKey, byte[])}. That structurally removes the
 * "raw-signing oracle" a VRF key would otherwise present — the exact surface the
 * EdDSA/ECVRF cross-protocol key-recovery attack needs.
 */
public final class VrfKey {

    private final byte[] seed;      // 32-byte SLIP-0010 node key (the RFC 9381 "SK")
    private final byte[] publicKey; // 32-byte VRF public key

    private VrfKey(byte[] seed, byte[] publicKey) {
        this.seed = seed;
        this.publicKey = publicKey;
    }

    /** Derive a VRF key from a 32-byte seed using the default backend. */
    public static VrfKey fromSeed(byte[] seed) {
        return fromSeed(seed, Crypto.defaultBackend());
    }

    public static VrfKey fromSeed(byte[] seed, CryptoBackend backend) {
        if (seed.length != 32) {
            throw new IllegalArgumentException("Ed25519 seed must be 32 bytes");
        }
        return new VrfKey(seed.clone(), backend.signSeedKeypair(seed).publicKey());
    }

    /** The 32-byte VRF public key (to register on-chain / verify proofs against). */
    public byte[] publicKey() {
        return publicKey.clone();
    }

    /** Package-private: the seed is readable only within the crypto package (by {@link Ecvrf}). */
    byte[] seed() {
        return seed;
    }
}

package tech.hearth.crypto;

/**
 * The three role keys, derived from one BIP-39 seed at separate paths. Signing
 * and VRF keys use different hardened SLIP-0010 role indices so their secret
 * scalars are unrelated — removing the EdDSA/ECVRF shared-key risk. BLS finality
 * keys live in their own EIP-2333 tree (different curve).
 */
public final class KeyTree {
    private KeyTree() {}

    private static final int COIN_TYPE = 9381; // placeholder — register a SLIP-0044 value
    private static final int ROLE_SIGNING = 0;
    private static final int ROLE_VRF = 1;

    public static String signingPath(int account) {
        return "m/44'/" + COIN_TYPE + "'/" + account + "'/" + ROLE_SIGNING + "'/0'";
    }

    public static String vrfPath(int account) {
        return "m/44'/" + COIN_TYPE + "'/" + account + "'/" + ROLE_VRF + "'/0'";
    }

    public static String blsPath(int account) {
        return "m/" + Bls.PURPOSE + "/" + COIN_TYPE + "/" + account + "/0";
    }

    /** Signing keypair using the default backend. */
    public static Ed25519.KeyPair signingKey(byte[] seed, int account) {
        return signingKey(seed, account, Crypto.defaultBackend());
    }

    /** VRF keypair using the default backend. */
    public static Ed25519.KeyPair vrfKey(byte[] seed, int account) {
        return vrfKey(seed, account, Crypto.defaultBackend());
    }

    /** BLS finality secret key using the default backend. */
    public static byte[] blsSecretKey(byte[] seed, int account) {
        return blsSecretKey(seed, account, Crypto.defaultBackend());
    }

    /** ed25519 keypair for signing transactions. */
    public static Ed25519.KeyPair signingKey(byte[] seed, int account, CryptoBackend backend) {
        return Ed25519.fromSeed(Slip10.derivePath(seed, signingPath(account), backend).privateKey(), backend);
    }

    /** ed25519 keypair for the VRF (its seed feeds {@link Ecvrf#prove}; publicKey is the VRF key). */
    public static Ed25519.KeyPair vrfKey(byte[] seed, int account, CryptoBackend backend) {
        return Ed25519.fromSeed(Slip10.derivePath(seed, vrfPath(account), backend).privateKey(), backend);
    }

    /** BLS12-381 finality secret key (32-byte big-endian scalar). */
    public static byte[] blsSecretKey(byte[] seed, int account, CryptoBackend backend) {
        return Bls.derivePath(seed, blsPath(account), backend);
    }
}

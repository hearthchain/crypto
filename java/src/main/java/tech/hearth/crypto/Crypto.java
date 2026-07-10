package tech.hearth.crypto;

/**
 * Entry point for backend selection and shared sizes. Picks the libsodium
 * backend when the native library is present, otherwise the pure-JVM one.
 * Override with {@code HEARTH_CRYPTO_BACKEND=sodium|jvm}.
 *
 * <p>The upper layers take a {@link CryptoBackend} explicitly; call
 * {@link #defaultBackend()} to get the auto-selected one.
 */
public final class Crypto {
    private Crypto() {}

    // Shared sizes (bytes).
    public static final int SIGN_SEED_BYTES = 32;
    public static final int SIGN_PUBLICKEY_BYTES = 32;
    public static final int SIGN_SECRETKEY_BYTES = 64;
    public static final int SIGN_BYTES = 64;
    public static final int SHA512_BYTES = 64;
    public static final int SHA256_BYTES = 32;
    public static final int POINT_BYTES = 32;
    public static final int SCALAR_BYTES = 32;
    public static final int SCALAR_NONREDUCED_BYTES = 64;

    private static final class Holder {
        private static final CryptoBackend BACKEND = select();

        private static CryptoBackend select() {
            String forced = System.getenv("HEARTH_CRYPTO_BACKEND");
            if (forced != null) {
                forced = forced.trim().toLowerCase();
                if (forced.equals("jvm")) {
                    return JvmBackend.INSTANCE;
                }
                if (forced.equals("sodium")) {
                    return new SodiumBackend(); // fail loudly if requested but absent
                }
            }
            try {
                SodiumBackend sodium = new SodiumBackend();
                sodium.selfTest();
                return sodium;
            } catch (Throwable t) {
                return JvmBackend.INSTANCE;
            }
        }
    }

    /** The auto-selected backend (libsodium if available, else pure JVM). */
    public static CryptoBackend defaultBackend() {
        return Holder.BACKEND;
    }
}

package tech.hearth.crypto;

import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

/**
 * A network-independent account identity: {@code SHA-256(publicKey)[0:20]}.
 *
 * <p>These 20 bytes ({@link #toBytes()}) are the canonical on-chain id — the
 * transaction recipient field, state keys, and equality all use them. The
 * <b>network is not part of the identity</b>; it only selects the human-readable
 * prefix (HRP) when rendering/parsing the bech32m string, so the HRP is supplied
 * at that boundary ({@link #toBech32(String)} / {@link #parse(String, String)})
 * rather than stored here. The same account on any network is one {@code Address}.
 *
 * <p>Immutable value type with content-based {@code equals}/{@code hashCode}.
 */
public record Address(byte[] hash) {

    public static final int HASH_LEN = 20;

    /** Canonical bech32m prefix for mainnet. */
    public static final String MAINNET_HRP = "hrth";
    /** Canonical bech32m prefix for testnet. */
    public static final String TESTNET_HRP = "thrth";

    // --- process-wide default HRP --------------------------------------------
    //
    // A node runs on a single network for its lifetime, so the HRP used by the
    // no-arg string helpers is a global set once at startup, via -Dhearth.hrp or
    // setDefaultHrp. It is fail-closed: if never set, defaultHrp() throws rather
    // than silently guessing. Callers that render for several networks should
    // pass the HRP explicitly instead.

    private static volatile String defaultHrp = validateHrp(System.getProperty("hearth.hrp"));

    /**
     * Set the process-wide default HRP used by the no-arg {@link #toBech32()} and
     * {@link #parse(String)} (pass {@code null} to clear it). Any well-formed
     * prefix works — {@link #MAINNET_HRP}, {@link #TESTNET_HRP}, or a devnet's own.
     *
     * @throws IllegalArgumentException if {@code hrp} is not a valid lowercase
     *     bech32 prefix
     */
    public static void setDefaultHrp(String hrp) {
        defaultHrp = validateHrp(hrp);
    }

    /**
     * The process-wide default HRP. Set it once with {@link #setDefaultHrp} or
     * {@code -Dhearth.hrp=<hrp>}.
     *
     * @throws IllegalStateException if no default has been configured
     */
    public static String defaultHrp() {
        String h = defaultHrp;
        if (h == null) {
            throw new IllegalStateException(
                    "default HRP not configured; call Address.setDefaultHrp(...), "
                            + "set -Dhearth.hrp=<hrp>, or pass an HRP explicitly");
        }
        return h;
    }

    /** Normalize (trim + lowercase) and validate a bech32 HRP; {@code null} passes through. */
    private static String validateHrp(String hrp) {
        if (hrp == null) {
            return null;
        }
        String h = hrp.trim().toLowerCase();
        if (h.isEmpty() || h.length() > 83) {
            throw new IllegalArgumentException("HRP must be 1..83 characters: '" + hrp + "'");
        }
        for (int i = 0; i < h.length(); i++) {
            char c = h.charAt(i);
            if (c < 'a' || c > 'z') {
                throw new IllegalArgumentException("HRP must be lowercase a-z: '" + hrp + "'");
            }
        }
        return h;
    }

    public Address {
        if (hash.length != HASH_LEN) {
            throw new IllegalArgumentException("hash must be " + HASH_LEN + " bytes");
        }
        hash = hash.clone(); // defensive copy — keep the record immutable
    }

    // --- construction --------------------------------------------------------

    /** Derive the address for an Ed25519 public key (default backend). */
    public static Address fromPublicKey(byte[] publicKey) {
        return fromPublicKey(publicKey, Crypto.defaultBackend());
    }

    public static Address fromPublicKey(byte[] publicKey, CryptoBackend backend) {
        if (publicKey.length != 32) {
            throw new IllegalArgumentException("public key must be 32 bytes");
        }
        return new Address(Arrays.copyOfRange(backend.sha256(publicKey), 0, HASH_LEN));
    }

    /**
     * Parse the raw 20-byte on-chain form, e.g. a transaction's recipient field.
     * Empty if the payload is malformed.
     */
    public static Optional<Address> fromBytes(byte[] payload) {
        if (payload.length != HASH_LEN) {
            return Optional.empty();
        }
        return Optional.of(new Address(payload));
    }

    /** Parse a bech32m string, requiring its HRP to equal {@code hrp}. */
    public static Optional<Address> parse(String s, String hrp) {
        String want = validateHrp(Objects.requireNonNull(hrp, "hrp"));
        return Bech32m.decode(s)
                .flatMap(d -> d.hrp().equals(want) ? fromBytes(d.data()) : Optional.empty());
    }

    /** Parse a bech32m string against the {@linkplain #defaultHrp() default HRP}. */
    public static Optional<Address> parse(String s) {
        return parse(s, defaultHrp());
    }

    /** The HRP a bech32m address string is encoded for, if it decodes. */
    public static Optional<String> hrpOf(String s) {
        return Bech32m.decode(s).map(Bech32m.Decoded::hrp);
    }

    // --- encoding ------------------------------------------------------------

    /** The canonical 20-byte on-chain form. */
    public byte[] toBytes() {
        return hash.clone();
    }

    /** The bech32m address string under the given HRP. */
    public String toBech32(String hrp) {
        return Bech32m.encode(validateHrp(Objects.requireNonNull(hrp, "hrp")), toBytes());
    }

    /** The bech32m address string under the {@linkplain #defaultHrp() default HRP}. */
    public String toBech32() {
        return toBech32(defaultHrp());
    }

    /** Debug form; uses {@link #toBech32()} on the default HRP. */
    @Override
    public String toString() {
        return toBech32();
    }

    // --- value semantics -----------------------------------------------------

    /** Returns a defensive copy so the internal hash can't be mutated. */
    @Override
    public byte[] hash() {
        return hash.clone();
    }

    @Override
    public boolean equals(Object o) {
        return this == o || (o instanceof Address a && Arrays.equals(hash, a.hash));
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(hash);
    }
}

package tech.hearth.crypto;

import java.util.Arrays;
import java.util.Optional;

/**
 * A network-independent account identity: {@code versionByte || SHA-256(publicKey)[0:20]}.
 *
 * <p>These 21 bytes ({@link #toBytes()}) are the canonical on-chain id — the
 * transaction recipient field, state keys, and equality all use them. The
 * <b>network is not part of the identity</b>; it only selects the human-readable
 * prefix when rendering/parsing the bech32m string, so it is supplied at that
 * boundary ({@link #toBech32(Network)} / {@link #parse(String, Network)}) rather
 * than stored here. The same account on mainnet and testnet is one {@code Address}.
 *
 * <p>Immutable value type with content-based {@code equals}/{@code hashCode}.
 */
public record Address(byte version, byte[] hash) {

    /** Address network — only relevant to the bech32m string form. */
    public enum Network {
        TESTNET("hrtht"),
        MAINNET("hrthm");

        private final String hrp;

        Network(String hrp) {
            this.hrp = hrp;
        }

        public String hrp() {
            return hrp;
        }

        static Optional<Network> byHrp(String hrp) {
            for (Network n : values()) {
                if (n.hrp.equals(hrp)) {
                    return Optional.of(n);
                }
            }
            return Optional.empty();
        }

        // --- process-wide default (for no-arg string helpers) ----------------
        //
        // A node runs on a single network for its lifetime, so a global default
        // set once at startup is appropriate. It is fail-closed: if never set,
        // getDefault() throws rather than silently guessing. Multi-network
        // callers should pass the Network explicitly instead.

        private static volatile Network defaultNetwork = fromSystemProperty();

        private static Network fromSystemProperty() {
            String p = System.getProperty("hearth.network");
            if (p == null) {
                return null;
            }
            return switch (p.trim().toLowerCase()) {
                case "mainnet", "hrthm" -> MAINNET;
                case "testnet", "hrtht" -> TESTNET;
                default -> throw new IllegalArgumentException("unknown hearth.network: " + p);
            };
        }

        /** Set the process-wide default network (pass {@code null} to clear it). */
        public static void setDefault(Network network) {
            defaultNetwork = network;
        }

        /**
         * The process-wide default network. Set it once with {@link #setDefault}
         * or {@code -Dhearth.network=mainnet|testnet}.
         *
         * @throws IllegalStateException if no default has been configured
         */
        public static Network getDefault() {
            Network n = defaultNetwork;
            if (n == null) {
                throw new IllegalStateException(
                        "default network not configured; call Address.Network.setDefault(...), "
                                + "set -Dhearth.network=mainnet|testnet, or pass a Network explicitly");
            }
            return n;
        }
    }

    public static final byte ED25519_VERSION = 0x00;
    public static final int HASH_LEN = 20;
    /** Length of the canonical on-chain payload: version(1) || hash(20). */
    public static final int PAYLOAD_LEN = 1 + HASH_LEN;

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
        return new Address(ED25519_VERSION, Arrays.copyOfRange(backend.sha256(publicKey), 0, HASH_LEN));
    }

    /**
     * Parse the raw 21-byte on-chain form (version || hash), e.g. a transaction's
     * recipient field. Empty if the payload is malformed.
     */
    public static Optional<Address> fromBytes(byte[] payload) {
        if (payload.length != PAYLOAD_LEN || payload[0] != ED25519_VERSION) {
            return Optional.empty();
        }
        return Optional.of(new Address(payload[0], Arrays.copyOfRange(payload, 1, PAYLOAD_LEN)));
    }

    /** Parse a bech32m string, requiring its HRP to match {@code network}. */
    public static Optional<Address> parse(String s, Network network) {
        return Bech32m.decode(s)
                .flatMap(d -> d.hrp().equals(network.hrp()) ? fromBytes(d.data()) : Optional.empty());
    }

    /** Parse a bech32m string against the {@linkplain Network#getDefault() default network}. */
    public static Optional<Address> parse(String s) {
        return parse(s, Network.getDefault());
    }

    /** The network a bech32m string is encoded for, if its HRP is recognized. */
    public static Optional<Network> networkOf(String s) {
        return Bech32m.decode(s).flatMap(d -> Network.byHrp(d.hrp()));
    }

    // --- encoding ------------------------------------------------------------

    /** The canonical 21-byte on-chain form: version || hash. */
    public byte[] toBytes() {
        byte[] out = new byte[PAYLOAD_LEN];
        out[0] = version;
        System.arraycopy(hash, 0, out, 1, HASH_LEN);
        return out;
    }

    /** The bech32m address string for a given network. */
    public String toBech32(Network network) {
        return Bech32m.encode(network.hrp(), toBytes());
    }

    /** The bech32m address string on the {@linkplain Network#getDefault() default network}. */
    public String toBech32() {
        return toBech32(Network.getDefault());
    }

    /** Network-independent debug form (hex of the 21-byte payload); use {@link #toBech32} to display. */
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
        return this == o || (o instanceof Address a && version == a.version && Arrays.equals(hash, a.hash));
    }

    @Override
    public int hashCode() {
        return 31 * version + Arrays.hashCode(hash);
    }
}

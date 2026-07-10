package tech.hearth.crypto;

import java.util.Arrays;
import java.util.Optional;

/**
 * Account addresses: {@code Bech32m(hrp, versionByte || SHA-256(publicKey)[0:20])}.
 * The per-network HRP is a UX guard against sending to the wrong network; it is
 * not replay protection (that belongs in the signed transaction).
 */
public final class Address {
    private Address() {}

    /** Address network. */
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
    }

    /** A decoded address. */
    public record Parsed(Network network, byte[] hash, byte version) {}

    public static final byte ED25519_VERSION = 0x00;
    private static final int HASH_LEN = 20;

    /** Derive the address string using the default backend. */
    public static String fromPublicKey(byte[] publicKey, Network network) {
        return fromPublicKey(publicKey, network, Crypto.defaultBackend());
    }

    /** Derive the address string for an Ed25519 public key on a given network. */
    public static String fromPublicKey(byte[] publicKey, Network network, CryptoBackend backend) {
        if (publicKey.length != 32) {
            throw new IllegalArgumentException("public key must be 32 bytes");
        }
        byte[] hash = Arrays.copyOfRange(backend.sha256(publicKey), 0, HASH_LEN);
        byte[] payload = new byte[1 + HASH_LEN];
        payload[0] = ED25519_VERSION;
        System.arraycopy(hash, 0, payload, 1, HASH_LEN);
        return Bech32m.encode(network.hrp(), payload);
    }

    /** Parse and validate an address string. */
    public static Optional<Parsed> parse(String s) {
        return Bech32m.decode(s).flatMap(d -> {
            byte[] payload = d.data();
            Optional<Network> network = Network.byHrp(d.hrp());
            if (network.isEmpty() || payload.length != HASH_LEN + 1 || payload[0] != ED25519_VERSION) {
                return Optional.empty();
            }
            return Optional.of(new Parsed(network.get(), Arrays.copyOfRange(payload, 1, payload.length), payload[0]));
        });
    }

    /** Parse and require a specific network (rejects cross-network addresses). */
    public static Optional<Parsed> parseFor(String s, Network expected) {
        return parse(s).filter(a -> a.network() == expected);
    }
}

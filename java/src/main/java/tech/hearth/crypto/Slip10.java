package tech.hearth.crypto;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * SLIP-0010 hierarchical key derivation for the ed25519 curve — the derivation
 * Ledger uses for Ed25519 accounts. The derived 32-byte node key is the Ed25519
 * seed. Only hardened derivation exists for ed25519.
 */
public final class Slip10 {
    private Slip10() {}

    /** A SLIP-0010 node. */
    public record Node(byte[] privateKey, byte[] chainCode) {}

    private static final byte[] ED25519_MASTER_KEY = "ed25519 seed".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final int HARDENED = 0x80000000;

    /** Master node using the default backend. */
    public static Node master(byte[] seed) {
        return master(seed, Crypto.defaultBackend());
    }

    /** One hardened child step using the default backend. */
    public static Node deriveChild(Node parent, int index) {
        return deriveChild(parent, index, Crypto.defaultBackend());
    }

    /** Derive along a path using the default backend. */
    public static Node derivePath(byte[] seed, String path) {
        return derivePath(seed, path, Crypto.defaultBackend());
    }

    /** Master node from a BIP-39 (or any) seed. */
    public static Node master(byte[] seed, CryptoBackend backend) {
        byte[] i = backend.hmacSha512(ED25519_MASTER_KEY, seed);
        return new Node(Arrays.copyOfRange(i, 0, 32), Arrays.copyOfRange(i, 32, 64));
    }

    /** One hardened child derivation step (the hardened bit is added automatically). */
    public static Node deriveChild(Node parent, int index, CryptoBackend backend) {
        int hardenedIndex = index | HARDENED;
        byte[] data = new byte[1 + 32 + 4];
        data[0] = 0;
        System.arraycopy(parent.privateKey, 0, data, 1, 32);
        data[33] = (byte) (hardenedIndex >>> 24);
        data[34] = (byte) (hardenedIndex >>> 16);
        data[35] = (byte) (hardenedIndex >>> 8);
        data[36] = (byte) hardenedIndex;
        byte[] i = backend.hmacSha512(parent.chainCode, data);
        return new Node(Arrays.copyOfRange(i, 0, 32), Arrays.copyOfRange(i, 32, 64));
    }

    /** Derive along a path such as "m/44'/9381'/0'/0'/0'". Every level is hardened. */
    public static Node derivePath(byte[] seed, String path, CryptoBackend backend) {
        Node node = master(seed, backend);
        for (int idx : parsePath(path)) {
            node = deriveChild(node, idx, backend);
        }
        return node;
    }

    public static int[] parsePath(String path) {
        String trimmed = path.trim();
        if (!trimmed.equals("m") && !trimmed.startsWith("m/")) {
            throw new IllegalArgumentException("path must start with 'm': " + path);
        }
        if (trimmed.equals("m")) {
            return new int[0];
        }
        String[] parts = trimmed.substring(2).split("/");
        List<Integer> out = new ArrayList<>(parts.length);
        for (String raw : parts) {
            String cleaned = raw.replaceAll("['hH]+$", "");
            long n;
            try {
                n = Long.parseLong(cleaned);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("bad path segment: '" + raw + "'");
            }
            if (n < 0 || (n & 0xFFFFFFFFL) >= (HARDENED & 0xFFFFFFFFL)) {
                throw new IllegalArgumentException("index out of range: " + raw);
            }
            out.add((int) n);
        }
        return out.stream().mapToInt(Integer::intValue).toArray();
    }
}

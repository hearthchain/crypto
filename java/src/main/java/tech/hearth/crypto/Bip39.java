package tech.hearth.crypto;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * BIP-39 mnemonic handling: checksum validation and seed derivation. The seed
 * derivation (PBKDF2-HMAC-SHA512, 2048 iterations) is built on the backend's
 * HMAC, so the whole pipeline stays on one primitive with no ambiguity about how
 * the password bytes are encoded (UTF-8, NFKD).
 */
public final class Bip39 {
    private Bip39() {}

    /**
     * The outcome of {@link #validate}: either {@link Valid} or {@link Invalid}.
     * Consume it by pattern matching, e.g.
     * {@code if (result instanceof Invalid(String reason)) ...}.
     */
    public sealed interface ValidationResult {
        /** True if the mnemonic is valid. */
        default boolean isValid() {
            return this instanceof Valid;
        }

        record Valid() implements ValidationResult {}

        record Invalid(String reason) implements ValidationResult {}
    }

    private static final int ITERATIONS = 2048;
    private static final int SEED_LEN = 64;
    private static final Set<Integer> VALID_WORD_COUNTS = Set.of(12, 15, 18, 21, 24);

    private static final List<String> WORDLIST = loadWordlist();
    private static final Map<String, Integer> WORD_INDEX = buildIndex(WORDLIST);

    private static List<String> loadWordlist() {
        try (InputStream in = Bip39.class.getResourceAsStream("/bip39/english.txt")) {
            if (in == null) {
                throw new IllegalStateException("bip39/english.txt resource missing");
            }
            List<String> words = new ArrayList<>(2048);
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String w = line.trim();
                    if (!w.isEmpty()) {
                        words.add(w);
                    }
                }
            }
            return List.copyOf(words);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static Map<String, Integer> buildIndex(List<String> words) {
        Map<String, Integer> index = new HashMap<>(words.size() * 2);
        for (int i = 0; i < words.size(); i++) {
            index.put(words.get(i), i);
        }
        return index;
    }

    /** Validate the BIP-39 checksum using the default backend. */
    public static ValidationResult validate(String mnemonic) {
        return validate(mnemonic, Crypto.defaultBackend());
    }

    /** Derive the seed with an empty passphrase using the default backend. */
    public static byte[] toSeed(String mnemonic) {
        return toSeed(mnemonic, "", Crypto.defaultBackend());
    }

    /** Derive the seed using the default backend. */
    public static byte[] toSeed(String mnemonic, String passphrase) {
        return toSeed(mnemonic, passphrase, Crypto.defaultBackend());
    }

    /** Validate the BIP-39 checksum. */
    public static ValidationResult validate(String mnemonic, CryptoBackend backend) {
        String[] words = normalize(mnemonic).split("\\s+");
        List<String> nonEmpty = new ArrayList<>();
        for (String w : words) {
            if (!w.isEmpty()) {
                nonEmpty.add(w);
            }
        }
        int n = nonEmpty.size();
        if (!VALID_WORD_COUNTS.contains(n)) {
            return new ValidationResult.Invalid("word count must be 12/15/18/21/24, got " + n);
        }
        int[] indices = new int[n];
        for (int i = 0; i < n; i++) {
            Integer idx = WORD_INDEX.get(nonEmpty.get(i));
            if (idx == null) {
                return new ValidationResult.Invalid("unknown word: '" + nonEmpty.get(i) + "'");
            }
            indices[i] = idx;
        }

        int totalBits = n * 11;
        int checksumBits = totalBits / 33;
        int entropyBits = totalBits - checksumBits;
        int[] bits = new int[totalBits];
        int pos = 0;
        for (int idx : indices) {
            for (int b = 10; b >= 0; b--) {
                bits[pos++] = (idx >> b) & 1;
            }
        }
        byte[] entropy = bitsToBytes(bits, entropyBits);
        byte[] hash = backend.sha256(entropy);
        for (int i = 0; i < checksumBits; i++) {
            int expected = (hash[i / 8] >> (7 - (i % 8))) & 1;
            if (bits[entropyBits + i] != expected) {
                return new ValidationResult.Invalid("checksum mismatch");
            }
        }
        return new ValidationResult.Valid();
    }

    /** Derive the 64-byte BIP-39 seed from a mnemonic and optional passphrase. */
    public static byte[] toSeed(String mnemonic, String passphrase, CryptoBackend backend) {
        byte[] password = normalize(mnemonic).getBytes(StandardCharsets.UTF_8);
        byte[] salt = normalize("mnemonic" + passphrase).getBytes(StandardCharsets.UTF_8);
        return pbkdf2HmacSha512(password, salt, ITERATIONS, SEED_LEN, backend);
    }

    private static String normalize(String s) {
        return Normalizer.normalize(s, Normalizer.Form.NFKD);
    }

    private static byte[] bitsToBytes(int[] bits, int count) {
        byte[] out = new byte[count / 8];
        for (int i = 0; i < count; i += 8) {
            int b = 0;
            for (int j = 0; j < 8; j++) {
                b = (b << 1) | bits[i + j];
            }
            out[i / 8] = (byte) b;
        }
        return out;
    }

    /** PBKDF2 with PRF = HMAC-SHA512, over the backend's HMAC. */
    private static byte[] pbkdf2HmacSha512(byte[] password, byte[] salt, int iterations, int dkLen,
                                           CryptoBackend backend) {
        int hLen = Crypto.SHA512_BYTES;
        int blocks = (int) Math.ceil((double) dkLen / hLen);
        byte[] dk = new byte[blocks * hLen];
        for (int i = 1; i <= blocks; i++) {
            byte[] intI = {(byte) (i >>> 24), (byte) (i >>> 16), (byte) (i >>> 8), (byte) i};
            byte[] u = backend.hmacSha512(password, concat(salt, intI));
            byte[] t = u.clone();
            for (int iter = 1; iter < iterations; iter++) {
                u = backend.hmacSha512(password, u);
                for (int j = 0; j < hLen; j++) {
                    t[j] ^= u[j];
                }
            }
            System.arraycopy(t, 0, dk, (i - 1) * hLen, hLen);
        }
        byte[] out = new byte[dkLen];
        System.arraycopy(dk, 0, out, 0, dkLen);
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}

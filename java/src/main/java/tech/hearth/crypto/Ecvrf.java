package tech.hearth.crypto;

import java.util.Arrays;
import java.util.Optional;

/**
 * ECVRF-EDWARDS25519-SHA512-TAI, the Ed25519 verifiable random function from
 * RFC 9381 (suite_string = 0x03). It reuses the exact Ed25519 key: the VRF secret
 * scalar is clamp(SHA-512(seed)) and the VRF public key is the Ed25519 public
 * key. Curve/scalar arithmetic runs on a {@link CryptoBackend}.
 */
public final class Ecvrf {
    private Ecvrf() {}

    private static final byte SUITE = 0x03;
    private static final int PT_LEN = 32;
    private static final int C_LEN = 16;
    private static final int PROOF_LEN = PT_LEN + C_LEN + PT_LEN; // 80
    private static final byte[] IDENTITY = identity();

    private static byte[] identity() {
        byte[] id = new byte[32];
        id[0] = 1;
        return id;
    }

    /** A VRF proof pi = Gamma(32) || c(16) || s(32). */
    public record Proof(byte[] gamma, byte[] c, byte[] s) {
        public byte[] bytes() {
            return concat(gamma, c, s);
        }
    }

    /** Result of proving: the proof and the VRF output beta (64 bytes). */
    public record ProveResult(Proof proof, byte[] beta) {}

    /** Prove using the default backend. */
    public static ProveResult prove(VrfKey key, byte[] alpha) {
        return prove(key, alpha, Crypto.defaultBackend());
    }

    /** Verify using the default backend. */
    public static Optional<byte[]> verify(byte[] publicKey, byte[] alpha, byte[] pi) {
        return verify(publicKey, alpha, pi, Crypto.defaultBackend());
    }

    /** Prove: returns the proof pi and the VRF output beta (64 bytes). */
    public static ProveResult prove(VrfKey key, byte[] alpha, CryptoBackend backend) {
        byte[] seed = key.seed();
        byte[] x = Ed25519.secretScalar(seed, backend);
        byte[] y = backend.scalarmultBaseNoclamp(x); // public key Y = x*B
        byte[] h = encodeToCurve(y, alpha, backend);
        byte[] gamma = backend.scalarmultNoclamp(x, h).orElseThrow(() -> new IllegalStateException("Gamma = x*H failed"));
        byte[] k = nonce(seed, h, backend);
        byte[] u = backend.scalarmultBaseNoclamp(k);                              // U = k*B
        byte[] v = backend.scalarmultNoclamp(k, h).orElseThrow(() -> new IllegalStateException("V = k*H failed"));
        byte[] c = challenge(y, h, gamma, u, v, backend);                         // 16 bytes
        byte[] c32 = new byte[PT_LEN];
        System.arraycopy(c, 0, c32, 0, C_LEN);
        byte[] s = backend.scalarAdd(k, backend.scalarMul(c32, x));               // s = k + c*x mod L
        Proof proof = new Proof(gamma, c, s);
        return new ProveResult(proof, proofToHash(proof, backend));
    }

    /** Verify a proof against the public key and alpha. Present with beta if valid. */
    public static Optional<byte[]> verify(byte[] publicKey, byte[] alpha, byte[] pi, CryptoBackend backend) {
        Optional<Proof> decoded = decode(pi);
        if (decoded.isEmpty()) {
            return Optional.empty();
        }
        Proof proof = decoded.get();
        byte[] h = encodeToCurve(publicKey, alpha, backend);
        byte[] c32 = new byte[PT_LEN];
        System.arraycopy(proof.c, 0, c32, 0, C_LEN);

        byte[] sB = backend.scalarmultBaseNoclamp(proof.s);
        Optional<byte[]> cY = backend.scalarmultNoclamp(c32, publicKey);
        if (cY.isEmpty()) {
            return Optional.empty();
        }
        Optional<byte[]> u = backend.pointSub(sB, cY.get());                  // U = s*B - c*Y
        if (u.isEmpty()) {
            return Optional.empty();
        }
        Optional<byte[]> sH = backend.scalarmultNoclamp(proof.s, h);
        Optional<byte[]> cGamma = backend.scalarmultNoclamp(c32, proof.gamma);
        if (sH.isEmpty() || cGamma.isEmpty()) {
            return Optional.empty();
        }
        Optional<byte[]> v = backend.pointSub(sH.get(), cGamma.get());        // V = s*H - c*Gamma
        if (v.isEmpty()) {
            return Optional.empty();
        }
        byte[] cPrime = challenge(publicKey, h, proof.gamma, u.get(), v.get(), backend);
        if (!Arrays.equals(cPrime, proof.c)) {
            return Optional.empty();
        }
        return Optional.of(proofToHash(proof, backend));
    }

    /** proof_to_hash using the default backend. */
    public static byte[] proofToHash(Proof proof) {
        return proofToHash(proof, Crypto.defaultBackend());
    }

    /** proof_to_hash: beta = SHA-512(suite || 0x03 || point_to_string(8*Gamma) || 0x00). */
    public static byte[] proofToHash(Proof proof, CryptoBackend backend) {
        byte[] gamma8 = cofactorClear(proof.gamma, backend).orElseThrow(() -> new IllegalStateException("8*Gamma failed"));
        return backend.sha512(concat(new byte[]{SUITE, 0x03}, gamma8, new byte[]{0x00}));
    }

    public static Optional<Proof> decode(byte[] pi) {
        if (pi.length != PROOF_LEN) {
            return Optional.empty();
        }
        return Optional.of(new Proof(
                Arrays.copyOfRange(pi, 0, PT_LEN),
                Arrays.copyOfRange(pi, PT_LEN, PT_LEN + C_LEN),
                Arrays.copyOfRange(pi, PT_LEN + C_LEN, PROOF_LEN)));
    }

    // --- internals -----------------------------------------------------------

    /** ECVRF_encode_to_curve_try_and_increment (RFC 9381 §5.4.1.1). */
    private static byte[] encodeToCurve(byte[] pkString, byte[] alpha, CryptoBackend backend) {
        for (int ctr = 0; ctr <= 255; ctr++) {
            byte[] hashString = backend.sha512(
                    concat(new byte[]{SUITE, 0x01}, pkString, alpha, new byte[]{(byte) ctr}, new byte[]{0x00}));
            byte[] candidate = Arrays.copyOfRange(hashString, 0, PT_LEN); // string_to_point(first 32 bytes)
            Optional<byte[]> cleared = cofactorClear(candidate, backend);
            if (cleared.isPresent() && !Arrays.equals(cleared.get(), IDENTITY)) {
                return cleared.get();
            }
        }
        throw new IllegalStateException("encode_to_curve: no valid point found");
    }

    /** Multiply a compressed point by cofactor 8 via three doublings (on-curve check only). */
    private static Optional<byte[]> cofactorClear(byte[] p, CryptoBackend backend) {
        Optional<byte[]> p2 = backend.pointAdd(p, p);
        if (p2.isEmpty()) {
            return Optional.empty();
        }
        Optional<byte[]> p4 = backend.pointAdd(p2.get(), p2.get());
        if (p4.isEmpty()) {
            return Optional.empty();
        }
        return backend.pointAdd(p4.get(), p4.get());
    }

    /** ECVRF_nonce_generation_RFC8032 (RFC 9381 §5.4.2.2). */
    private static byte[] nonce(byte[] seed, byte[] hString, CryptoBackend backend) {
        byte[] kString = backend.sha512(concat(Ed25519.noncePrefix(seed, backend), hString));
        return backend.scalarReduce(kString);
    }

    /** ECVRF_challenge_generation (RFC 9381 §5.4.3): first 16 bytes. */
    private static byte[] challenge(byte[] y, byte[] h, byte[] gamma, byte[] u, byte[] v, CryptoBackend backend) {
        byte[] full = backend.sha512(concat(new byte[]{SUITE, 0x02}, y, h, gamma, u, v, new byte[]{0x00}));
        return Arrays.copyOfRange(full, 0, C_LEN);
    }

    private static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int pos = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, pos, p.length);
            pos += p.length;
        }
        return out;
    }
}

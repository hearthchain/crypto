package tech.hearth.crypto;

import java.util.Optional;

/**
 * The set of primitives the upper layers (BIP-39, SLIP-0010, Ed25519, ECVRF,
 * BLS derivation) need. Two interchangeable implementations exist:
 *
 * <ul>
 *   <li>{@link SodiumBackend} — libsodium via the Panama Foreign Function &amp; Memory API;</li>
 *   <li>{@link JvmBackend} — pure JVM (JDK digests/HMAC + BigInteger edwards25519).</li>
 * </ul>
 *
 * They are byte-for-byte compatible (RFC 8032 / RFC 9381), so callers behave the
 * same with or without a native libsodium present.
 */
public interface CryptoBackend {

    /** An Ed25519 keypair in libsodium's expanded form. */
    record RawKeypair(byte[] publicKey, byte[] secretKey) {}

    String name();

    byte[] sha512(byte[] in);

    byte[] sha256(byte[] in);

    byte[] hmacSha512(byte[] key, byte[] msg);

    byte[] hmacSha256(byte[] key, byte[] msg);

    /** Deterministically expand a 32-byte seed into (publicKey[32], secretKey[64] = seed||pk). */
    RawKeypair signSeedKeypair(byte[] seed);

    byte[] signDetached(byte[] msg, byte[] secretKey);

    boolean verifyDetached(byte[] sig, byte[] msg, byte[] publicKey);

    /** Ed25519 point addition on compressed points (on-curve check only). Empty if off-curve. */
    Optional<byte[]> pointAdd(byte[] p, byte[] q);

    /** Ed25519 point subtraction p - q on compressed points (on-curve check only). */
    Optional<byte[]> pointSub(byte[] p, byte[] q);

    /** q = n * p, scalar used verbatim (no clamping). Empty if the point is rejected. */
    Optional<byte[]> scalarmultNoclamp(byte[] n, byte[] p);

    /** q = n * B, scalar used verbatim (no clamping). */
    byte[] scalarmultBaseNoclamp(byte[] n);

    /** z = x * y mod L. */
    byte[] scalarMul(byte[] x, byte[] y);

    /** z = x + y mod L. */
    byte[] scalarAdd(byte[] x, byte[] y);

    /** Reduce a 64-byte little-endian value mod L to a 32-byte scalar. */
    byte[] scalarReduce(byte[] wide);
}

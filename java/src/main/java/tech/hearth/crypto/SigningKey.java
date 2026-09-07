package tech.hearth.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * An Ed25519 key used to <em>sign</em> (transactions, blocks, consensus messages).
 *
 * <p>It is a distinct type from {@link VrfKey} on purpose: the two roles must
 * never share a key, because EdDSA and ECVRF over the same scalar enable a
 * cross-protocol nonce-collision key-recovery attack. Keeping them as separate
 * types makes that mistake a compile error rather than a convention.
 *
 * <h2>One key type, several ways in</h2>
 *
 * <p>Every Ed25519 secret is, at signing time, a pair: the secret scalar {@code a}
 * and the nonce prefix. A seed is just a compact way to generate that pair by
 * hashing (RFC 8032 §5.1.5). So a key derived from a mnemonic and a key imported
 * from a raw scalar are the same kind of object here, and callers never branch on
 * where one came from:
 *
 * <ul>
 *   <li>{@link #fromSeed(byte[])} — a 32-byte seed, what {@link KeyTree} derives
 *       from a mnemonic;</li>
 *   <li>{@link #fromExpandedKey(byte[])} — the pair directly,
 *       {@code scalar ‖ noncePrefix};</li>
 *   <li>{@link #fromScalar(byte[])} — a bare scalar, with the prefix derived from
 *       it (see below).</li>
 * </ul>
 *
 * <p>{@link #publicKey()}, {@link #toAddress()}, {@link #sign} and
 * {@link #toExpandedKey()} behave identically for all of them, and a verifier
 * cannot tell them apart. The seedless entries exist because some keys cannot
 * have a seed — the motivating case being GPU vanity-address search, where
 * candidates are walked by repeated point addition ({@code A_i = A_{i-1} + B},
 * ~100x cheaper per candidate than a scalar multiplication) and no seed hashes to
 * the scalar that wins.
 *
 * <p>What a seedless key genuinely cannot do is anything that needs the seed
 * <em>as such</em>: it has no mnemonic and no SLIP-0010 path, so it cannot
 * produce the account's sibling {@link VrfKey}, which lives at a different path
 * anyway. {@link #toX25519()} depends on the scalar's shape rather than on
 * provenance — see its documentation.
 *
 * <h2>Handling the nonce prefix</h2>
 *
 * <p>The prefix is <b>secret key material</b>, not a label. EdDSA's per-signature
 * nonce is {@code r = SHA-512(prefix ‖ message)}; anyone who learns the prefix
 * learns {@code r} for any message this key signs, and recovers the secret scalar
 * from a single signature via {@code a = (S - r) / k}. A generator that produces
 * keys in expanded form must draw the prefix from a CSPRNG — never from the
 * search counter, the candidate index, or anything else derived from public data.
 * {@link #fromScalar} sidesteps that trap by deriving the prefix from the secret
 * scalar itself.
 */
public final class SigningKey {

    /** Size of the expanded secret: scalar(32) || nonce prefix(32). */
    public static final int EXPANDED_KEY_BYTES = 64;

    /**
     * Domain separation tag for {@link #fromScalar}: the prefix is
     * {@code SHA-512(SCALAR_EXPAND_DST ‖ scalar)[32..64]}. Fixed across all five
     * implementations — changing it changes every key imported that way.
     */
    public static final String SCALAR_EXPAND_DST = "hearth-chain/ed25519-scalar-expand/v1";

    private static final int SCALAR_BYTES = 32;

    private final byte[] scalar;    // 32-byte secret scalar a
    private final byte[] prefix;    // 32-byte nonce prefix
    private final byte[] publicKey; // 32-byte compressed point A = [a]B
    private final byte[] secretKey; // libsodium's 64-byte seed||publicKey, when a seed produced this key

    private SigningKey(byte[] scalar, byte[] prefix, byte[] publicKey, byte[] secretKey) {
        this.scalar = scalar;
        this.prefix = prefix;
        this.publicKey = publicKey;
        this.secretKey = secretKey;
    }

    // --- construction --------------------------------------------------------

    /** Derive a signing key from a 32-byte seed using the default backend. */
    public static SigningKey fromSeed(byte[] seed) {
        return fromSeed(seed, Crypto.defaultBackend());
    }

    public static SigningKey fromSeed(byte[] seed, CryptoBackend backend) {
        if (seed.length != 32) {
            throw new IllegalArgumentException("Ed25519 seed must be 32 bytes");
        }
        CryptoBackend.RawKeypair raw = backend.signSeedKeypair(seed);
        return new SigningKey(Ed25519.secretScalar(seed, backend), Ed25519.noncePrefix(seed, backend),
                raw.publicKey(), raw.secretKey());
    }

    /** Import an expanded key using the default backend. */
    public static SigningKey fromExpandedKey(byte[] expanded) {
        return fromExpandedKey(expanded, Crypto.defaultBackend());
    }

    /**
     * Import {@code scalar[32] || noncePrefix[32]}, both little-endian as RFC 8032
     * writes them.
     *
     * <p>The scalar is taken verbatim. It is <b>not</b> required to be clamped —
     * that is the point of this entry: a scalar arrived at by repeated point
     * addition has no reason to satisfy the clamping bits, and EdDSA does not need
     * it to (clamping guards X25519's cofactor and a ladder's timing, not the
     * signature equation). It is not required to be reduced mod L either, so a
     * seed-derived key exports and re-imports byte-for-byte.
     *
     * @throws IllegalArgumentException if the length is wrong, the scalar's high
     *     bit is set (above the 255-bit range the group operations accept), or the
     *     scalar is zero mod L (whose public key is the identity point, which
     *     {@link Ed25519#verify} rejects for every signature)
     */
    public static SigningKey fromExpandedKey(byte[] expanded, CryptoBackend backend) {
        if (expanded.length != EXPANDED_KEY_BYTES) {
            throw new IllegalArgumentException("expanded key must be " + EXPANDED_KEY_BYTES + " bytes");
        }
        return fromParts(Arrays.copyOfRange(expanded, 0, SCALAR_BYTES),
                Arrays.copyOfRange(expanded, SCALAR_BYTES, EXPANDED_KEY_BYTES), backend);
    }

    /** Import a bare scalar using the default backend. */
    public static SigningKey fromScalar(byte[] scalar) {
        return fromScalar(scalar, Crypto.defaultBackend());
    }

    /**
     * Import a bare 32-byte secret scalar, deriving the nonce prefix from it as
     * {@code SHA-512(}{@link #SCALAR_EXPAND_DST}{@code  ‖ scalar)[32..64]} — the
     * same shape RFC 8032 uses when it splits a hash into scalar and prefix, with
     * the scalar in place of the seed.
     *
     * <p>This is what a key generator that only ever computes scalars — a vanity
     * grinder walking {@code a_i = a_{i-1} + 1} — should emit: 32 bytes, and any
     * implementation reconstructs the identical key. It also removes the sharpest
     * edge in {@link #fromExpandedKey}, since the prefix is then a one-way
     * function of secret material rather than something the generator has to
     * remember to draw from a CSPRNG.
     *
     * <p>The resulting key is an ordinary {@code SigningKey}, indistinguishable
     * from any other once built. Note that the derived prefix is not the one any
     * seed would produce, so this is not a way back to a mnemonic.
     *
     * @throws IllegalArgumentException on the same conditions as
     *     {@link #fromExpandedKey}
     */
    public static SigningKey fromScalar(byte[] scalar, CryptoBackend backend) {
        if (scalar.length != SCALAR_BYTES) {
            throw new IllegalArgumentException("secret scalar must be " + SCALAR_BYTES + " bytes");
        }
        byte[] dst = SCALAR_EXPAND_DST.getBytes(StandardCharsets.UTF_8);
        byte[] input = new byte[dst.length + SCALAR_BYTES];
        System.arraycopy(dst, 0, input, 0, dst.length);
        System.arraycopy(scalar, 0, input, dst.length, SCALAR_BYTES);
        byte[] prefix = Arrays.copyOfRange(backend.sha512(input), 32, 64);
        return fromParts(scalar.clone(), prefix, backend);
    }

    private static SigningKey fromParts(byte[] scalar, byte[] prefix, CryptoBackend backend) {
        if ((scalar[31] & 0x80) != 0) {
            throw new IllegalArgumentException("secret scalar must be below 2^255 (high bit clear)");
        }
        if (isZeroModL(scalar, backend)) {
            throw new IllegalArgumentException("secret scalar must not be zero mod L");
        }
        return new SigningKey(scalar, prefix, Ed25519.publicKeyFromScalar(scalar, backend), null);
    }

    // --- use -----------------------------------------------------------------

    /** The 32-byte Ed25519 public key. */
    public byte[] publicKey() {
        return publicKey.clone();
    }

    /**
     * This key's (network-independent) account address. Render it with
     * {@link Address#toBech32(String)} or {@link Address#toBech32()}.
     */
    public Address toAddress() {
        return Address.fromPublicKey(publicKey);
    }

    /** Produce a detached Ed25519 signature over {@code message} (default backend). */
    public byte[] sign(byte[] message) {
        return sign(message, Crypto.defaultBackend());
    }

    /**
     * Produce a detached Ed25519 signature over {@code message}.
     *
     * <p>A key that came from a seed takes the backend's native signing path
     * (libsodium's, when present), which wants the seed; any other key takes
     * {@link Ed25519#signWithScalar}. That is an internal shortcut, not a
     * difference in behaviour — the two are the same computation and, for the same
     * key, return the same bytes, which {@code CryptoVectorsTest} pins.
     */
    public byte[] sign(byte[] message, CryptoBackend backend) {
        if (secretKey != null) {
            return backend.signDetached(message, secretKey);
        }
        return Ed25519.signWithScalar(message, scalar, prefix, publicKey, backend);
    }

    // --- export --------------------------------------------------------------

    /**
     * The expanded secret, {@code scalar[32] || noncePrefix[32]} — the form
     * {@link #fromExpandedKey} takes back, and everything needed to sign. For a
     * seed-derived key this is {@code clamp(SHA-512(seed)[0..32]) ‖
     * SHA-512(seed)[32..64]}, i.e. exactly what signing uses internally anyway.
     *
     * <p>Treat the result as the private key it is.
     */
    public byte[] toExpandedKey() {
        byte[] out = new byte[EXPANDED_KEY_BYTES];
        System.arraycopy(scalar, 0, out, 0, SCALAR_BYTES);
        System.arraycopy(prefix, 0, out, SCALAR_BYTES, SCALAR_BYTES);
        return out;
    }

    /** Deliberately not the secret key — {@link #toExpandedKey()} is explicit about that. */
    @Override
    public String toString() {
        return "SigningKey[pk=" + Hex.encode(publicKey) + "]";
    }

    // --- other key material --------------------------------------------------

    /**
     * The X25519 keypair sharing this identity's secret scalar — the standard
     * ed25519-to-curve25519 conversion (libsodium's
     * {@code crypto_sign_ed25519_{pk,sk}_to_curve25519}). A TD that publishes a
     * single ed25519 identity key converts it this way to get the recipient key
     * {@link Hpke} encrypts to, instead of managing a second keypair.
     *
     * <p>Available whenever the secret scalar is clamped, which is a property of
     * the key material and not of where the key came from: every seed-derived key
     * qualifies, before or after a round trip through {@link #toExpandedKey()},
     * and so does an imported key whose scalar happens to be clamped.
     *
     * @throws IllegalStateException if the scalar is not clamped. X25519 clamps
     *     whatever secret it is handed, so an unclamped scalar would silently act
     *     as a <em>different</em> key from the public key returned alongside it —
     *     there is no correct conversion to return.
     */
    public X25519.Keypair toX25519() {
        return toX25519(Crypto.defaultBackend());
    }

    public X25519.Keypair toX25519(CryptoBackend backend) {
        if ((scalar[0] & 0x07) != 0 || (scalar[31] & 0xC0) != 0x40) {
            throw new IllegalStateException(
                    "X25519 conversion needs a clamped secret scalar; this key's scalar is not clamped");
        }
        return new X25519.Keypair(Ed25519.toX25519PublicKey(publicKey), scalar.clone());
    }

    // --- internals -----------------------------------------------------------

    /** Whether the scalar reduces to zero mod L, using only backend primitives. */
    private static boolean isZeroModL(byte[] scalar, CryptoBackend backend) {
        byte[] wide = new byte[Crypto.SCALAR_NONREDUCED_BYTES];
        System.arraycopy(scalar, 0, wide, 0, SCALAR_BYTES); // little-endian: the high half stays zero
        for (byte b : backend.scalarReduce(wide)) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }
}

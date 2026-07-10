package tech.hearth.crypto;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.util.List;
import java.util.Optional;

/**
 * libsodium binding via the Java Foreign Function &amp; Memory API (Panama). No
 * JNI and no extra native artifacts — it {@code dlopen}s the platform libsodium
 * and drives it directly. Constructing the backend loads the library; if that
 * fails the constructor throws and callers fall back to {@link JvmBackend}.
 */
public final class SodiumBackend implements CryptoBackend {

    private static final ValueLayout.OfInt INT = ValueLayout.JAVA_INT;
    private static final ValueLayout.OfLong LONG = ValueLayout.JAVA_LONG;
    private static final java.lang.foreign.AddressLayout PTR = ValueLayout.ADDRESS;

    private static final int SIGN_PUBLICKEY_BYTES = 32;
    private static final int SIGN_SECRETKEY_BYTES = 64;
    private static final int SIGN_BYTES = 64;
    private static final int SHA512_BYTES = 64;
    private static final int SHA256_BYTES = 32;
    private static final int POINT_BYTES = 32;
    private static final int SCALAR_BYTES = 32;

    private final Linker linker = Linker.nativeLinker();
    private final SymbolLookup lookup;

    private final MethodHandle hSeedKeypair;
    private final MethodHandle hSignDetached;
    private final MethodHandle hVerifyDetached;
    private final MethodHandle hSha512;
    private final MethodHandle hSha256;
    private final MethodHandle hPointAdd;
    private final MethodHandle hPointSub;
    private final MethodHandle hScalarmultNoclamp;
    private final MethodHandle hScalarmultBaseNC;
    private final MethodHandle hScalarMul;
    private final MethodHandle hScalarAdd;
    private final MethodHandle hScalarReduce;
    private final MethodHandle hHmac512Statebytes;
    private final MethodHandle hHmac512Init;
    private final MethodHandle hHmac512Update;
    private final MethodHandle hHmac512Final;
    private final MethodHandle hHmac256Statebytes;
    private final MethodHandle hHmac256Init;
    private final MethodHandle hHmac256Update;
    private final MethodHandle hHmac256Final;

    public SodiumBackend() {
        this.lookup = loadLibrary();
        this.hSeedKeypair = handle("crypto_sign_seed_keypair", FunctionDescriptor.of(INT, PTR, PTR, PTR));
        this.hSignDetached = handle("crypto_sign_detached", FunctionDescriptor.of(INT, PTR, PTR, PTR, LONG, PTR));
        this.hVerifyDetached = handle("crypto_sign_verify_detached", FunctionDescriptor.of(INT, PTR, PTR, LONG, PTR));
        this.hSha512 = handle("crypto_hash_sha512", FunctionDescriptor.of(INT, PTR, PTR, LONG));
        this.hSha256 = handle("crypto_hash_sha256", FunctionDescriptor.of(INT, PTR, PTR, LONG));
        this.hPointAdd = handle("crypto_core_ed25519_add", FunctionDescriptor.of(INT, PTR, PTR, PTR));
        this.hPointSub = handle("crypto_core_ed25519_sub", FunctionDescriptor.of(INT, PTR, PTR, PTR));
        this.hScalarmultNoclamp = handle("crypto_scalarmult_ed25519_noclamp", FunctionDescriptor.of(INT, PTR, PTR, PTR));
        this.hScalarmultBaseNC = handle("crypto_scalarmult_ed25519_base_noclamp", FunctionDescriptor.of(INT, PTR, PTR));
        this.hScalarMul = handle("crypto_core_ed25519_scalar_mul", FunctionDescriptor.ofVoid(PTR, PTR, PTR));
        this.hScalarAdd = handle("crypto_core_ed25519_scalar_add", FunctionDescriptor.ofVoid(PTR, PTR, PTR));
        this.hScalarReduce = handle("crypto_core_ed25519_scalar_reduce", FunctionDescriptor.ofVoid(PTR, PTR));
        this.hHmac512Statebytes = handle("crypto_auth_hmacsha512_statebytes", FunctionDescriptor.of(LONG));
        this.hHmac512Init = handle("crypto_auth_hmacsha512_init", FunctionDescriptor.of(INT, PTR, PTR, LONG));
        this.hHmac512Update = handle("crypto_auth_hmacsha512_update", FunctionDescriptor.of(INT, PTR, PTR, LONG));
        this.hHmac512Final = handle("crypto_auth_hmacsha512_final", FunctionDescriptor.of(INT, PTR, PTR));
        this.hHmac256Statebytes = handle("crypto_auth_hmacsha256_statebytes", FunctionDescriptor.of(LONG));
        this.hHmac256Init = handle("crypto_auth_hmacsha256_init", FunctionDescriptor.of(INT, PTR, PTR, LONG));
        this.hHmac256Update = handle("crypto_auth_hmacsha256_update", FunctionDescriptor.of(INT, PTR, PTR, LONG));
        this.hHmac256Final = handle("crypto_auth_hmacsha256_final", FunctionDescriptor.of(INT, PTR, PTR));

        MethodHandle init = handle("sodium_init", FunctionDescriptor.of(INT));
        if (callInt(init) < 0) {
            throw new IllegalStateException("sodium_init() failed");
        }
    }

    private SymbolLookup loadLibrary() {
        List<String> candidates = List.of(
                System.getenv().getOrDefault("HEARTH_SODIUM_LIB", ""),
                "libsodium.dylib",
                "libsodium.so.23",
                "libsodium.so",
                "/opt/homebrew/lib/libsodium.dylib",
                "/usr/local/lib/libsodium.dylib",
                "/usr/lib/x86_64-linux-gnu/libsodium.so.23");
        for (String name : candidates) {
            if (name.isEmpty()) {
                continue;
            }
            try {
                return SymbolLookup.libraryLookup(name, Arena.global());
            } catch (RuntimeException ignored) {
                // try next candidate
            }
        }
        throw new UnsatisfiedLinkError(
                "Could not load libsodium. Install it (macOS: `brew install libsodium`, "
                        + "Debian/Ubuntu: `apt install libsodium23`) or set HEARTH_SODIUM_LIB.");
    }

    private MethodHandle handle(String name, FunctionDescriptor desc) {
        MemorySegment sym = lookup.find(name)
                .orElseThrow(() -> new UnsatisfiedLinkError("libsodium symbol not found: " + name));
        return linker.downcallHandle(sym, desc);
    }

    /** Force native loading + a trivial call so callers can probe availability. */
    public void selfTest() {
        sha512(new byte[0]);
    }

    @Override
    public String name() {
        return "libsodium";
    }

    @Override
    public byte[] sha512(byte[] in) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(SHA512_BYTES);
            callInt(hSha512, out, seg(arena, in), Long.valueOf(in.length));
            return read(out, SHA512_BYTES);
        }
    }

    @Override
    public byte[] sha256(byte[] in) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(SHA256_BYTES);
            callInt(hSha256, out, seg(arena, in), Long.valueOf(in.length));
            return read(out, SHA256_BYTES);
        }
    }

    @Override
    public RawKeypair signSeedKeypair(byte[] seed) {
        if (seed.length != 32) {
            throw new IllegalArgumentException("seed must be 32 bytes");
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment pk = arena.allocate(SIGN_PUBLICKEY_BYTES);
            MemorySegment sk = arena.allocate(SIGN_SECRETKEY_BYTES);
            if (callInt(hSeedKeypair, pk, sk, seg(arena, seed)) != 0) {
                throw new RuntimeException("crypto_sign_seed_keypair failed");
            }
            return new RawKeypair(read(pk, SIGN_PUBLICKEY_BYTES), read(sk, SIGN_SECRETKEY_BYTES));
        }
    }

    @Override
    public byte[] signDetached(byte[] msg, byte[] secretKey) {
        if (secretKey.length != SIGN_SECRETKEY_BYTES) {
            throw new IllegalArgumentException("secret key must be 64 bytes");
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment sig = arena.allocate(SIGN_BYTES);
            int rc = callInt(hSignDetached, sig, MemorySegment.NULL, seg(arena, msg),
                    Long.valueOf(msg.length), seg(arena, secretKey));
            if (rc != 0) {
                throw new RuntimeException("crypto_sign_detached failed");
            }
            return read(sig, SIGN_BYTES);
        }
    }

    @Override
    public boolean verifyDetached(byte[] sig, byte[] msg, byte[] publicKey) {
        if (sig.length != SIGN_BYTES || publicKey.length != SIGN_PUBLICKEY_BYTES) {
            return false;
        }
        try (Arena arena = Arena.ofConfined()) {
            return callInt(hVerifyDetached, seg(arena, sig), seg(arena, msg),
                    Long.valueOf(msg.length), seg(arena, publicKey)) == 0;
        }
    }

    @Override
    public Optional<byte[]> pointAdd(byte[] p, byte[] q) {
        return twoPointOp(hPointAdd, p, q);
    }

    @Override
    public Optional<byte[]> pointSub(byte[] p, byte[] q) {
        return twoPointOp(hPointSub, p, q);
    }

    private Optional<byte[]> twoPointOp(MethodHandle op, byte[] p, byte[] q) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment r = arena.allocate(POINT_BYTES);
            int rc = callInt(op, r, seg(arena, p), seg(arena, q));
            return rc == 0 ? Optional.of(read(r, POINT_BYTES)) : Optional.empty();
        }
    }

    @Override
    public Optional<byte[]> scalarmultNoclamp(byte[] n, byte[] p) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(POINT_BYTES);
            int rc = callInt(hScalarmultNoclamp, out, seg(arena, n), seg(arena, p));
            return rc == 0 ? Optional.of(read(out, POINT_BYTES)) : Optional.empty();
        }
    }

    @Override
    public byte[] scalarmultBaseNoclamp(byte[] n) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(POINT_BYTES);
            if (callInt(hScalarmultBaseNC, out, seg(arena, n)) != 0) {
                throw new RuntimeException("crypto_scalarmult_ed25519_base_noclamp failed");
            }
            return read(out, POINT_BYTES);
        }
    }

    @Override
    public byte[] scalarMul(byte[] x, byte[] y) {
        return scalarBinOp(hScalarMul, x, y);
    }

    @Override
    public byte[] scalarAdd(byte[] x, byte[] y) {
        return scalarBinOp(hScalarAdd, x, y);
    }

    private byte[] scalarBinOp(MethodHandle op, byte[] x, byte[] y) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment z = arena.allocate(SCALAR_BYTES);
            callVoid(op, z, seg(arena, x), seg(arena, y));
            return read(z, SCALAR_BYTES);
        }
    }

    @Override
    public byte[] scalarReduce(byte[] wide) {
        if (wide.length != 64) {
            throw new IllegalArgumentException("input must be 64 bytes");
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment r = arena.allocate(SCALAR_BYTES);
            callVoid(hScalarReduce, r, seg(arena, wide));
            return read(r, SCALAR_BYTES);
        }
    }

    @Override
    public byte[] hmacSha512(byte[] key, byte[] msg) {
        return hmac(hHmac512Statebytes, hHmac512Init, hHmac512Update, hHmac512Final, SHA512_BYTES, key, msg);
    }

    @Override
    public byte[] hmacSha256(byte[] key, byte[] msg) {
        return hmac(hHmac256Statebytes, hHmac256Init, hHmac256Update, hHmac256Final, SHA256_BYTES, key, msg);
    }

    private byte[] hmac(MethodHandle statebytes, MethodHandle init, MethodHandle update, MethodHandle fin,
                        int outLen, byte[] key, byte[] msg) {
        try (Arena arena = Arena.ofConfined()) {
            long stateLen = callLong(statebytes);
            MemorySegment state = arena.allocate(stateLen, 16);
            if (callInt(init, state, seg(arena, key), Long.valueOf(key.length)) != 0) {
                throw new RuntimeException("hmac init failed");
            }
            if (callInt(update, state, seg(arena, msg), Long.valueOf(msg.length)) != 0) {
                throw new RuntimeException("hmac update failed");
            }
            MemorySegment out = arena.allocate(outLen);
            if (callInt(fin, state, out) != 0) {
                throw new RuntimeException("hmac final failed");
            }
            return read(out, outLen);
        }
    }

    // --- FFI helpers ---------------------------------------------------------

    private static MemorySegment seg(Arena arena, byte[] bytes) {
        MemorySegment s = arena.allocate(Math.max(bytes.length, 1));
        MemorySegment.copy(bytes, 0, s, ValueLayout.JAVA_BYTE, 0L, bytes.length);
        return s;
    }

    private static byte[] read(MemorySegment s, int len) {
        byte[] a = new byte[len];
        MemorySegment.copy(s, ValueLayout.JAVA_BYTE, 0L, a, 0, len);
        return a;
    }

    private static int callInt(MethodHandle h, Object... args) {
        try {
            return (Integer) h.invokeWithArguments(args);
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    private static long callLong(MethodHandle h, Object... args) {
        try {
            return (Long) h.invokeWithArguments(args);
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    private static void callVoid(MethodHandle h, Object... args) {
        try {
            h.invokeWithArguments(args);
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }
}

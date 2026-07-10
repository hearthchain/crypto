package hearth.crypto

import java.lang.foreign.*
import java.lang.invoke.MethodHandle

/** Thin binding to libsodium via the Java 22+ Foreign Function & Memory API
  * (Project Panama). No JNI, no extra native artifacts to ship — we just
  * `dlopen` the platform libsodium and drive it directly.
  *
  * Every method here maps 1:1 onto a libsodium C entry point and works purely
  * on `Array[Byte]`; the segment/arena bookkeeping stays inside this file.
  */
object SodiumBackend extends CryptoBackend:

  def name: String = "libsodium"

  /** Force native loading + a trivial call so callers can probe availability. */
  def selfTest(): Unit = { sha512(Array.emptyByteArray); () }

  // --- Constants (from sodium headers, stable across releases) -------------
  private val SignPublicKeyBytes: Int = 32 // crypto_sign_PUBLICKEYBYTES
  private val SignSecretKeyBytes: Int = 64 // crypto_sign_SECRETKEYBYTES (seed||pk)
  private val SignBytes: Int          = 64 // crypto_sign_BYTES
  private val Sha512Bytes: Int        = 64
  private val Sha256Bytes: Int        = 32
  private val PointBytes: Int         = 32 // crypto_core_ed25519_BYTES
  private val ScalarBytes: Int        = 32 // crypto_core_ed25519_SCALARBYTES
  private val ScalarNonReducedBytes: Int = 64 // crypto_core_ed25519_NONREDUCEDSCALARBYTES
  private val SignSeedBytes: Int      = 32 // crypto_sign_SEEDBYTES

  private val linker: Linker = Linker.nativeLinker()
  private val lookup: SymbolLookup =
    val candidates = List(
      Option(System.getenv("HEARTH_SODIUM_LIB")),
      Some("libsodium.dylib"),
      Some("libsodium.so.23"),
      Some("libsodium.so"),
      Some("/opt/homebrew/lib/libsodium.dylib"),
      Some("/usr/local/lib/libsodium.dylib"),
      Some("/usr/lib/x86_64-linux-gnu/libsodium.so.23")
    ).flatten
    candidates.iterator
      .flatMap(name => scala.util.Try(SymbolLookup.libraryLookup(name, Arena.global())).toOption)
      .nextOption()
      .getOrElse(
        throw new UnsatisfiedLinkError(
          "Could not load libsodium. Install it (macOS: `brew install libsodium`, " +
            "Debian/Ubuntu: `apt install libsodium23`) or set HEARTH_SODIUM_LIB to the .dylib/.so path."
        )
      )

  private def handle(name: String, desc: FunctionDescriptor): MethodHandle =
    val sym = lookup
      .find(name)
      .orElseThrow(() => new UnsatisfiedLinkError(s"libsodium symbol not found: $name"))
    linker.downcallHandle(sym, desc)

  private val PTR  = ValueLayout.ADDRESS
  private val INT  = ValueLayout.JAVA_INT
  private val LONG = ValueLayout.JAVA_LONG // size_t / unsigned long long on LP64

  private val hInit               = handle("sodium_init", FunctionDescriptor.of(INT))
  private val hSeedKeypair        = handle("crypto_sign_seed_keypair", FunctionDescriptor.of(INT, PTR, PTR, PTR))
  private val hSignDetached       = handle("crypto_sign_detached", FunctionDescriptor.of(INT, PTR, PTR, PTR, LONG, PTR))
  private val hVerifyDetached     = handle("crypto_sign_verify_detached", FunctionDescriptor.of(INT, PTR, PTR, LONG, PTR))
  private val hSha512             = handle("crypto_hash_sha512", FunctionDescriptor.of(INT, PTR, PTR, LONG))
  private val hSha256             = handle("crypto_hash_sha256", FunctionDescriptor.of(INT, PTR, PTR, LONG))
  private val hPointAdd           = handle("crypto_core_ed25519_add", FunctionDescriptor.of(INT, PTR, PTR, PTR))
  private val hPointSub           = handle("crypto_core_ed25519_sub", FunctionDescriptor.of(INT, PTR, PTR, PTR))
  private val hScalarmultNoclamp  = handle("crypto_scalarmult_ed25519_noclamp", FunctionDescriptor.of(INT, PTR, PTR, PTR))
  private val hScalarmultBaseNC   = handle("crypto_scalarmult_ed25519_base_noclamp", FunctionDescriptor.of(INT, PTR, PTR))
  private val hScalarMul          = handle("crypto_core_ed25519_scalar_mul", FunctionDescriptor.ofVoid(PTR, PTR, PTR))
  private val hScalarAdd          = handle("crypto_core_ed25519_scalar_add", FunctionDescriptor.ofVoid(PTR, PTR, PTR))
  private val hScalarReduce       = handle("crypto_core_ed25519_scalar_reduce", FunctionDescriptor.ofVoid(PTR, PTR))
  private val hHmac512Statebytes  = handle("crypto_auth_hmacsha512_statebytes", FunctionDescriptor.of(LONG))
  private val hHmac512Init        = handle("crypto_auth_hmacsha512_init", FunctionDescriptor.of(INT, PTR, PTR, LONG))
  private val hHmac512Update      = handle("crypto_auth_hmacsha512_update", FunctionDescriptor.of(INT, PTR, PTR, LONG))
  private val hHmac512Final       = handle("crypto_auth_hmacsha512_final", FunctionDescriptor.of(INT, PTR, PTR))
  private val hHmac256Statebytes  = handle("crypto_auth_hmacsha256_statebytes", FunctionDescriptor.of(LONG))
  private val hHmac256Init        = handle("crypto_auth_hmacsha256_init", FunctionDescriptor.of(INT, PTR, PTR, LONG))
  private val hHmac256Update      = handle("crypto_auth_hmacsha256_update", FunctionDescriptor.of(INT, PTR, PTR, LONG))
  private val hHmac256Final       = handle("crypto_auth_hmacsha256_final", FunctionDescriptor.of(INT, PTR, PTR))

  // sodium_init() is idempotent and thread-safe; must be called before use.
  private val initResult: Int = hInit.invokeWithArguments().asInstanceOf[Integer].intValue
  if initResult < 0 then throw new IllegalStateException("sodium_init() failed")

  // --- Small helpers -------------------------------------------------------

  private inline def withArena[A](f: Arena => A): A =
    val arena = Arena.ofConfined()
    try f(arena)
    finally arena.close()

  private def seg(arena: Arena, bytes: Array[Byte]): MemorySegment =
    val s = arena.allocate(bytes.length.toLong.max(1L))
    MemorySegment.copy(bytes, 0, s, ValueLayout.JAVA_BYTE, 0L, bytes.length)
    s

  private def out(arena: Arena, len: Int): MemorySegment = arena.allocate(len.toLong)

  private def read(s: MemorySegment, len: Int): Array[Byte] =
    val a = new Array[Byte](len)
    MemorySegment.copy(s, ValueLayout.JAVA_BYTE, 0L, a, 0, len)
    a

  // --- Public API ----------------------------------------------------------

  /** Deterministically expand a 32-byte seed into an Ed25519 keypair.
    * Returns (publicKey[32], secretKey[64] = seed||publicKey).
    */
  def signSeedKeypair(seed: Array[Byte]): (Array[Byte], Array[Byte]) =
    require(seed.length == SignSeedBytes, "seed must be 32 bytes")
    withArena { a =>
      val pk = out(a, SignPublicKeyBytes)
      val sk = out(a, SignSecretKeyBytes)
      val rc = hSeedKeypair.invokeWithArguments(pk, sk, seg(a, seed)).asInstanceOf[Integer].intValue
      if rc != 0 then throw new RuntimeException("crypto_sign_seed_keypair failed")
      (read(pk, SignPublicKeyBytes), read(sk, SignSecretKeyBytes))
    }

  /** Detached Ed25519 (EdDSA / RFC 8032) signature over `msg`. */
  def signDetached(msg: Array[Byte], secretKey: Array[Byte]): Array[Byte] =
    require(secretKey.length == SignSecretKeyBytes, "secret key must be 64 bytes")
    withArena { a =>
      val sig = out(a, SignBytes)
      val rc = hSignDetached
        .invokeWithArguments(sig, MemorySegment.NULL, seg(a, msg), java.lang.Long.valueOf(msg.length.toLong), seg(a, secretKey))
        .asInstanceOf[Integer].intValue
      if rc != 0 then throw new RuntimeException("crypto_sign_detached failed")
      read(sig, SignBytes)
    }

  /** Verify a detached Ed25519 signature. */
  def verifyDetached(sig: Array[Byte], msg: Array[Byte], publicKey: Array[Byte]): Boolean =
    require(sig.length == SignBytes, "signature must be 64 bytes")
    require(publicKey.length == SignPublicKeyBytes, "public key must be 32 bytes")
    withArena { a =>
      hVerifyDetached
        .invokeWithArguments(seg(a, sig), seg(a, msg), java.lang.Long.valueOf(msg.length.toLong), seg(a, publicKey))
        .asInstanceOf[Integer].intValue == 0
    }

  def sha512(in: Array[Byte]): Array[Byte] = withArena { a =>
    val o = out(a, Sha512Bytes)
    hSha512.invokeWithArguments(o, seg(a, in), java.lang.Long.valueOf(in.length.toLong))
    read(o, Sha512Bytes)
  }

  def sha256(in: Array[Byte]): Array[Byte] = withArena { a =>
    val o = out(a, Sha256Bytes)
    hSha256.invokeWithArguments(o, seg(a, in), java.lang.Long.valueOf(in.length.toLong))
    read(o, Sha256Bytes)
  }

  /** Ed25519 point addition on compressed points. Only checks the operands are
    * on the curve (not subgroup / small-order), which is exactly what RFC 9381
    * try-and-increment cofactor clearing needs. Returns None if off-curve.
    */
  def pointAdd(p: Array[Byte], q: Array[Byte]): Option[Array[Byte]] = withArena { a =>
    val r = out(a, PointBytes)
    val rc = hPointAdd.invokeWithArguments(r, seg(a, p), seg(a, q)).asInstanceOf[Integer].intValue
    if rc == 0 then Some(read(r, PointBytes)) else None
  }

  /** Ed25519 point subtraction p - q on compressed points (on-curve check only). */
  def pointSub(p: Array[Byte], q: Array[Byte]): Option[Array[Byte]] = withArena { a =>
    val r = out(a, PointBytes)
    val rc = hPointSub.invokeWithArguments(r, seg(a, p), seg(a, q)).asInstanceOf[Integer].intValue
    if rc == 0 then Some(read(r, PointBytes)) else None
  }

  /** q = n * p on Ed25519, scalar used verbatim (no clamping). Requires p on the
    * prime-order subgroup (libsodium enforces this). Returns None if rejected.
    */
  def scalarmultNoclamp(n: Array[Byte], p: Array[Byte]): Option[Array[Byte]] = withArena { a =>
    val q = out(a, PointBytes)
    val rc = hScalarmultNoclamp.invokeWithArguments(q, seg(a, n), seg(a, p)).asInstanceOf[Integer].intValue
    if rc == 0 then Some(read(q, PointBytes)) else None
  }

  /** q = n * B on Ed25519, scalar used verbatim (no clamping). */
  def scalarmultBaseNoclamp(n: Array[Byte]): Array[Byte] = withArena { a =>
    val q = out(a, PointBytes)
    val rc = hScalarmultBaseNC.invokeWithArguments(q, seg(a, n)).asInstanceOf[Integer].intValue
    if rc != 0 then throw new RuntimeException("crypto_scalarmult_ed25519_base_noclamp failed")
    read(q, PointBytes)
  }

  /** z = x * y mod L (group order). Inputs are 32-byte little-endian scalars. */
  def scalarMul(x: Array[Byte], y: Array[Byte]): Array[Byte] = withArena { a =>
    val z = out(a, ScalarBytes)
    hScalarMul.invokeWithArguments(z, seg(a, x), seg(a, y))
    read(z, ScalarBytes)
  }

  /** z = x + y mod L. */
  def scalarAdd(x: Array[Byte], y: Array[Byte]): Array[Byte] = withArena { a =>
    val z = out(a, ScalarBytes)
    hScalarAdd.invokeWithArguments(z, seg(a, x), seg(a, y))
    read(z, ScalarBytes)
  }

  /** Reduce a 64-byte little-endian value mod L to a 32-byte scalar. */
  def scalarReduce(wide: Array[Byte]): Array[Byte] =
    require(wide.length == ScalarNonReducedBytes, "input must be 64 bytes")
    withArena { a =>
      val r = out(a, ScalarBytes)
      hScalarReduce.invokeWithArguments(r, seg(a, wide))
      read(r, ScalarBytes)
    }

  /** HMAC-SHA-512 with an arbitrary-length key (the streaming API accepts any
    * key length, unlike the one-shot `crypto_auth_hmacsha512`).
    */
  def hmacSha512(key: Array[Byte], msg: Array[Byte]): Array[Byte] =
    hmac(hHmac512Statebytes, hHmac512Init, hHmac512Update, hHmac512Final, Sha512Bytes, key, msg)

  /** HMAC-SHA-256 with an arbitrary-length key (used by EIP-2333 HKDF). */
  def hmacSha256(key: Array[Byte], msg: Array[Byte]): Array[Byte] =
    hmac(hHmac256Statebytes, hHmac256Init, hHmac256Update, hHmac256Final, Sha256Bytes, key, msg)

  private def hmac(statebytes: MethodHandle, init: MethodHandle, update: MethodHandle, fin: MethodHandle,
                   outLen: Int, key: Array[Byte], msg: Array[Byte]): Array[Byte] = withArena { a =>
    val stateLen = statebytes.invokeWithArguments().asInstanceOf[java.lang.Long].longValue
    val state = a.allocate(stateLen, 16L)
    val ki = init.invokeWithArguments(state, seg(a, key), java.lang.Long.valueOf(key.length.toLong)).asInstanceOf[Integer].intValue
    if ki != 0 then throw new RuntimeException("hmac init failed")
    val ku = update.invokeWithArguments(state, seg(a, msg), java.lang.Long.valueOf(msg.length.toLong)).asInstanceOf[Integer].intValue
    if ku != 0 then throw new RuntimeException("hmac update failed")
    val o = out(a, outLen)
    val kf = fin.invokeWithArguments(state, o).asInstanceOf[Integer].intValue
    if kf != 0 then throw new RuntimeException("hmac final failed")
    read(o, outLen)
  }

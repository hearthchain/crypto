package hearth.crypto

/** The set of primitives the upper layers (BIP-39, SLIP-0010, Ed25519, ECVRF)
  * need. Two interchangeable implementations exist:
  *
  *  - [[SodiumBackend]] — libsodium via Panama FFI (fast, audited native code);
  *  - [[JvmBackend]]    — pure JVM (JDK digests/HMAC + BigInteger edwards25519).
  *
  * They are byte-for-byte compatible (RFC 8032 / RFC 9381), so a node runs the
  * same way with or without a native libsodium present.
  */
trait CryptoBackend:
  def name: String

  def sha512(in: Array[Byte]): Array[Byte]
  def sha256(in: Array[Byte]): Array[Byte]
  def hmacSha512(key: Array[Byte], msg: Array[Byte]): Array[Byte]
  def hmacSha256(key: Array[Byte], msg: Array[Byte]): Array[Byte]

  def signSeedKeypair(seed: Array[Byte]): (Array[Byte], Array[Byte])
  def signDetached(msg: Array[Byte], secretKey: Array[Byte]): Array[Byte]
  def verifyDetached(sig: Array[Byte], msg: Array[Byte], publicKey: Array[Byte]): Boolean

  def pointAdd(p: Array[Byte], q: Array[Byte]): Option[Array[Byte]]
  def pointSub(p: Array[Byte], q: Array[Byte]): Option[Array[Byte]]
  def scalarmultNoclamp(n: Array[Byte], p: Array[Byte]): Option[Array[Byte]]
  def scalarmultBaseNoclamp(n: Array[Byte]): Array[Byte]
  def scalarMul(x: Array[Byte], y: Array[Byte]): Array[Byte]
  def scalarAdd(x: Array[Byte], y: Array[Byte]): Array[Byte]
  def scalarReduce(wide: Array[Byte]): Array[Byte]

/** Facade the rest of the codebase talks to. Picks the libsodium backend when
  * the native library is present, otherwise falls back to the pure-JVM one.
  *
  * Override with the env var `HEARTH_CRYPTO_BACKEND=sodium|jvm`.
  */
object Crypto extends CryptoBackend:

  // Shared sizes (bytes).
  val SignSeedBytes: Int         = 32
  val SignPublicKeyBytes: Int    = 32
  val SignSecretKeyBytes: Int    = 64
  val SignBytes: Int             = 64
  val Sha512Bytes: Int           = 64
  val Sha256Bytes: Int           = 32
  val PointBytes: Int            = 32
  val ScalarBytes: Int           = 32
  val ScalarNonReducedBytes: Int = 64

  lazy val backend: CryptoBackend = select()

  private def select(): CryptoBackend =
    Option(System.getenv("HEARTH_CRYPTO_BACKEND")).map(_.trim.toLowerCase) match
      case Some("jvm")    => JvmBackend
      case Some("sodium") => SodiumBackend // fail loudly if explicitly requested but absent
      case _ =>
        try
          SodiumBackend.selfTest()
          SodiumBackend
        catch case _: Throwable => JvmBackend

  def name: String = backend.name

  def sha512(in: Array[Byte]): Array[Byte]                              = backend.sha512(in)
  def sha256(in: Array[Byte]): Array[Byte]                              = backend.sha256(in)
  def hmacSha512(key: Array[Byte], msg: Array[Byte]): Array[Byte]       = backend.hmacSha512(key, msg)
  def hmacSha256(key: Array[Byte], msg: Array[Byte]): Array[Byte]       = backend.hmacSha256(key, msg)
  def signSeedKeypair(seed: Array[Byte]): (Array[Byte], Array[Byte])    = backend.signSeedKeypair(seed)
  def signDetached(msg: Array[Byte], sk: Array[Byte]): Array[Byte]      = backend.signDetached(msg, sk)
  def verifyDetached(sig: Array[Byte], msg: Array[Byte], pk: Array[Byte]): Boolean = backend.verifyDetached(sig, msg, pk)
  def pointAdd(p: Array[Byte], q: Array[Byte]): Option[Array[Byte]]     = backend.pointAdd(p, q)
  def pointSub(p: Array[Byte], q: Array[Byte]): Option[Array[Byte]]     = backend.pointSub(p, q)
  def scalarmultNoclamp(n: Array[Byte], p: Array[Byte]): Option[Array[Byte]] = backend.scalarmultNoclamp(n, p)
  def scalarmultBaseNoclamp(n: Array[Byte]): Array[Byte]               = backend.scalarmultBaseNoclamp(n)
  def scalarMul(x: Array[Byte], y: Array[Byte]): Array[Byte]           = backend.scalarMul(x, y)
  def scalarAdd(x: Array[Byte], y: Array[Byte]): Array[Byte]           = backend.scalarAdd(x, y)
  def scalarReduce(wide: Array[Byte]): Array[Byte]                     = backend.scalarReduce(wide)

/** Default backend used by the upper layers unless one is passed explicitly
  * (tests pass [[SodiumBackend]] / [[JvmBackend]] directly to exercise both).
  */
given defaultCryptoBackend: CryptoBackend = Crypto

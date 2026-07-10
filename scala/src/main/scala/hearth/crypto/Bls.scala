package hearth.crypto

import java.math.BigInteger

/** BLS12-381 key **derivation** per EIP-2333 (key generation) and EIP-2334
  * (path convention). This is the BLS analog of SLIP-0010.
  *
  * Only derivation is implemented here — it is pure HKDF-SHA-256 + SHA-256 +
  * `mod r` arithmetic and needs no pairing library. Signing/aggregation/PoP
  * would require a pairing backend (e.g. `blst`) and are intentionally omitted.
  *
  * Unlike SLIP-0010, EIP-2333 has NO hardened/non-hardened distinction: every
  * child is derived from the parent secret key (Lamport + HKDF), so all keys are
  * hardened-equivalent and paths are written without the `'` marker. Do not add
  * apostrophes to a BLS path — it is not the same notation as an ed25519 path.
  */
object Bls:

  /** BLS12-381 subgroup order r. */
  val R: BigInteger =
    new BigInteger("52435875175126190479447740508185965837690552500527637822603658699938581184513")

  /** EIP-2334 purpose (the curve id). */
  val Purpose: Long = 12381L

  private val KeyGenSalt = "BLS-SIG-KEYGEN-SALT-".getBytes("US-ASCII")
  private val Sha256Len  = 32
  private val LamportChunks = 255

  /** Master secret key from a seed (>= 32 bytes). Returns a 32-byte big-endian scalar. */
  def deriveMasterSk(seed: Array[Byte])(using b: CryptoBackend): Array[Byte] =
    require(seed.length >= 32, "EIP-2333 seed must be at least 32 bytes")
    hkdfModR(seed)

  /** One child derivation step. `index` is a uint32 (0 .. 2^32-1). */
  def deriveChildSk(parentSk: Array[Byte], index: Long)(using b: CryptoBackend): Array[Byte] =
    require(index >= 0 && index <= 0xffffffffL, "index must fit in uint32")
    hkdfModR(parentSkToLamportPk(parentSk, index))

  /** Derive along an EIP-2334 path such as "m/12381/9381/0/0". */
  def derivePath(seed: Array[Byte], path: String)(using b: CryptoBackend): Array[Byte] =
    parsePath(path).foldLeft(deriveMasterSk(seed))((sk, idx) => deriveChildSk(sk, idx))

  def parsePath(path: String): Vector[Long] =
    val trimmed = path.trim
    require(trimmed == "m" || trimmed.startsWith("m/"), s"path must start with 'm': $path")
    if trimmed == "m" then Vector.empty
    else
      trimmed.drop(2).split("/").toVector.map { raw =>
        require(!raw.contains('\''), s"BLS (EIP-2333) has no hardened notation; drop the ' in '$raw'")
        val n = raw.toLongOption.getOrElse(throw new IllegalArgumentException(s"bad path segment: '$raw'"))
        require(n >= 0 && n <= 0xffffffffL, s"index out of uint32 range: $raw")
        n
      }

  // --- EIP-2333 internals --------------------------------------------------

  /** HKDF_mod_r(IKM): the loop reseeds the salt with SHA-256 until SK != 0. */
  private def hkdfModR(ikm: Array[Byte], keyInfo: Array[Byte] = Array.emptyByteArray)(using b: CryptoBackend): Array[Byte] =
    val L = 48 // ceil((3 * ceil(log2(r))) / 16)
    var salt = KeyGenSalt
    var sk = BigInteger.ZERO
    while sk.signum() == 0 do
      salt = b.sha256(salt)
      val prk = b.hmacSha256(salt, ikm ++ i2osp(0, 1))          // HKDF-Extract(salt, IKM || I2OSP(0,1))
      val okm = hkdfExpand(prk, keyInfo ++ i2osp(L, 2), L)      // HKDF-Expand(PRK, key_info || I2OSP(L,2), L)
      sk = os2ip(okm).mod(R)
    i2osp(sk, 32)

  private def parentSkToLamportPk(parentSk: Array[Byte], index: Long)(using b: CryptoBackend): Array[Byte] =
    val salt   = i2osp(index, 4)
    val ikm    = i2ospBytes(parentSk, 32)
    val notIkm = ikm.map(x => (~x).toByte)
    val lamport0 = ikmToLamportSk(salt, ikm)
    val lamport1 = ikmToLamportSk(salt, notIkm)
    val buf = new Array[Byte](2 * LamportChunks * Sha256Len)
    var i = 0
    while i < LamportChunks do
      System.arraycopy(b.sha256(lamport0(i)), 0, buf, i * Sha256Len, Sha256Len)
      i += 1
    while i < 2 * LamportChunks do
      System.arraycopy(b.sha256(lamport1(i - LamportChunks)), 0, buf, i * Sha256Len, Sha256Len)
      i += 1
    b.sha256(buf)

  private def ikmToLamportSk(salt: Array[Byte], ikm: Array[Byte])(using b: CryptoBackend): Array[Array[Byte]] =
    val prk = b.hmacSha256(salt, ikm)
    val okm = hkdfExpand(prk, Array.emptyByteArray, LamportChunks * Sha256Len)
    Array.tabulate(LamportChunks)(i => okm.slice(i * Sha256Len, (i + 1) * Sha256Len))

  /** HKDF-Expand (RFC 5869) with HMAC-SHA-256. `length` must be <= 255*32. */
  private def hkdfExpand(prk: Array[Byte], info: Array[Byte], length: Int)(using b: CryptoBackend): Array[Byte] =
    require(length <= 255 * Sha256Len, "HKDF-Expand length exceeds 255*HashLen")
    val out = new Array[Byte](length)
    var t   = Array.emptyByteArray
    var pos = 0
    var counter = 1
    while pos < length do
      t = b.hmacSha256(prk, t ++ info ++ Array(counter.toByte))
      val n = math.min(Sha256Len, length - pos)
      System.arraycopy(t, 0, out, pos, n)
      pos += n
      counter += 1
    out

  // --- primitives ----------------------------------------------------------

  /** Integer-to-octet-string, big-endian, fixed length. */
  private def i2osp(value: Long, len: Int): Array[Byte] =
    val out = new Array[Byte](len)
    var v = value
    var i = len - 1
    while i >= 0 do
      out(i) = (v & 0xff).toByte
      v >>>= 8
      i -= 1
    out

  private def i2osp(value: BigInteger, len: Int): Array[Byte] = i2ospBytes(bigToMinimalBE(value), len)

  /** Left-pad (or validate) big-endian bytes to exactly `len`. */
  private def i2ospBytes(be: Array[Byte], len: Int): Array[Byte] =
    require(be.length <= len, "value too large for I2OSP length")
    val out = new Array[Byte](len)
    System.arraycopy(be, 0, out, len - be.length, be.length)
    out

  private def bigToMinimalBE(v: BigInteger): Array[Byte] =
    val raw = v.toByteArray            // big-endian, possibly with a leading sign byte
    if raw.length > 1 && raw(0) == 0.toByte then raw.tail else raw

  private def os2ip(bytes: Array[Byte]): BigInteger = new BigInteger(1, bytes)

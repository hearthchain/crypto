package hearth.crypto

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import Ed25519Math.*

/** Pure-JVM implementation of [[CryptoBackend]]: JDK digests/HMAC plus the
  * BigInteger edwards25519 arithmetic in [[Ed25519Math]]. Produces byte-for-byte
  * the same Ed25519 signatures (RFC 8032) and ECVRF proofs (RFC 9381) as the
  * libsodium backend, so it is a drop-in fallback when no native lib is present.
  *
  * Not constant-time; use [[SodiumBackend]] in production where available.
  */
object JvmBackend extends CryptoBackend:

  def name: String = "jvm"

  def sha512(in: Array[Byte]): Array[Byte] = MessageDigest.getInstance("SHA-512").digest(in)
  def sha256(in: Array[Byte]): Array[Byte] = MessageDigest.getInstance("SHA-256").digest(in)

  def hmacSha512(key: Array[Byte], msg: Array[Byte]): Array[Byte] = hmac("HmacSHA512", key, msg)
  def hmacSha256(key: Array[Byte], msg: Array[Byte]): Array[Byte] = hmac("HmacSHA256", key, msg)

  private def hmac(algorithm: String, key: Array[Byte], msg: Array[Byte]): Array[Byte] =
    val mac = Mac.getInstance(algorithm)
    // Empty HMAC keys are legal but SecretKeySpec rejects them; pad to a zero byte.
    val k = if key.isEmpty then Array[Byte](0) else key
    mac.init(new SecretKeySpec(k, algorithm))
    mac.doFinal(msg)

  def signSeedKeypair(seed: Array[Byte]): (Array[Byte], Array[Byte]) =
    require(seed.length == 32, "seed must be 32 bytes")
    val a  = scalarFromLE(clamp(sha512(seed).slice(0, 32)))
    val pk = encode(mulBase(a))
    (pk, seed ++ pk)

  def signDetached(msg: Array[Byte], secretKey: Array[Byte]): Array[Byte] =
    require(secretKey.length == 64, "secret key must be 64 bytes")
    val seed = secretKey.slice(0, 32)
    val pub  = secretKey.slice(32, 64)
    val h    = sha512(seed)
    val a    = scalarFromLE(clamp(h.slice(0, 32)))
    val prefix = h.slice(32, 64)
    val r    = scalarFromLE(sha512(prefix ++ msg)).mod(L)
    val rB   = encode(mulBase(r))
    val k    = scalarFromLE(sha512(rB ++ pub ++ msg)).mod(L)
    val s    = r.add(k.multiply(a)).mod(L)
    rB ++ scalarToLE32(s)

  def verifyDetached(sig: Array[Byte], msg: Array[Byte], publicKey: Array[Byte]): Boolean =
    if sig.length != 64 || publicKey.length != 32 then return false
    val rBytes = sig.slice(0, 32)
    val s      = scalarFromLE(sig.slice(32, 64))
    if s.compareTo(L) >= 0 then return false
    (decode(publicKey), decode(rBytes)) match
      case (Some(aPt), Some(rPt)) =>
        val k = scalarFromLE(sha512(rBytes ++ publicKey ++ msg)).mod(L)
        val lhs = mulBase(s)                // [S]B
        val rhs = add(rPt, mul(k, aPt))     // R + [k]A
        lhs.x.equals(rhs.x) && lhs.y.equals(rhs.y)
      case _ => false

  def pointAdd(p: Array[Byte], q: Array[Byte]): Option[Array[Byte]] =
    for a <- decode(p); b <- decode(q) yield encode(add(a, b))

  def pointSub(p: Array[Byte], q: Array[Byte]): Option[Array[Byte]] =
    for a <- decode(p); b <- decode(q) yield encode(add(a, negate(b)))

  def scalarmultNoclamp(n: Array[Byte], p: Array[Byte]): Option[Array[Byte]] =
    val scalar = scalarFromLE(n)
    decode(p) match
      case Some(pt) if scalar.signum() != 0 && isOnMainSubgroup(pt) =>
        val q = mul(scalar, pt)
        if isIdentity(q) then None else Some(encode(q)) // libsodium rejects an infinity result
      case _ => None

  def scalarmultBaseNoclamp(n: Array[Byte]): Array[Byte] = encode(mulBase(scalarFromLE(n)))

  def scalarMul(x: Array[Byte], y: Array[Byte]): Array[Byte] =
    scalarToLE32(scalarFromLE(x).multiply(scalarFromLE(y)).mod(L))

  def scalarAdd(x: Array[Byte], y: Array[Byte]): Array[Byte] =
    scalarToLE32(scalarFromLE(x).add(scalarFromLE(y)).mod(L))

  def scalarReduce(wide: Array[Byte]): Array[Byte] =
    require(wide.length == 64, "input must be 64 bytes")
    scalarToLE32(scalarFromLE(wide).mod(L))

  private def clamp(a: Array[Byte]): Array[Byte] =
    val c = a.clone()
    c(0)  = (c(0) & 0xf8).toByte
    c(31) = ((c(31) & 0x7f) | 0x40).toByte
    c

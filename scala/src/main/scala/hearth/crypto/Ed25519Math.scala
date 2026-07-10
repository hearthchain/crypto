package hearth.crypto

import java.math.BigInteger

/** Self-contained edwards25519 field/group arithmetic (RFC 8032 / RFC 7748) in
  * `BigInteger`. Correctness-first, not constant-time — it exists purely as the
  * pure-JVM fallback for [[JvmBackend]] when native libsodium is unavailable.
  *
  * Points are affine (x, y) mod p; encoding is the 32-byte little-endian RFC 8032
  * compressed form. Addition uses the complete twisted-Edwards formula (a = -1).
  */
private[crypto] object Ed25519Math:

  private val TWO = BigInteger.valueOf(2)

  val p: BigInteger = TWO.pow(255).subtract(BigInteger.valueOf(19))
  /** Group order L. */
  val L: BigInteger = TWO.pow(252).add(new BigInteger("27742317777372353535851937790883648493"))
  private val d: BigInteger =
    BigInteger.valueOf(-121665).multiply(inv(BigInteger.valueOf(121666))).mod(p)
  private val I: BigInteger = // sqrt(-1) mod p
    TWO.modPow(p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(4)), p)

  final case class Point(x: BigInteger, y: BigInteger)

  val Zero: Point = Point(BigInteger.ZERO, BigInteger.ONE) // identity
  val B: Point =
    val by = BigInteger.valueOf(4).multiply(inv(BigInteger.valueOf(5))).mod(p)
    val bx = recoverX(by, 0).get
    Point(bx, by)

  private def inv(a: BigInteger): BigInteger = a.modPow(p.subtract(TWO), p)
  private def m(a: BigInteger, b: BigInteger): BigInteger = a.multiply(b).mod(p)

  def add(pt1: Point, pt2: Point): Point =
    val x1y2 = m(pt1.x, pt2.y)
    val y1x2 = m(pt1.y, pt2.x)
    val y1y2 = m(pt1.y, pt2.y)
    val x1x2 = m(pt1.x, pt2.x)
    val dxxyy = m(m(d, m(x1x2, y1y2)), BigInteger.ONE)
    val x3 = m(x1y2.add(y1x2), inv(BigInteger.ONE.add(dxxyy)))
    val y3 = m(y1y2.add(x1x2), inv(BigInteger.ONE.subtract(dxxyy).mod(p)))
    Point(x3, y3)

  def negate(pt: Point): Point = Point(p.subtract(pt.x).mod(p), pt.y)

  /** n * pt via double-and-add (n treated as a non-negative integer). */
  def mul(n: BigInteger, pt: Point): Point =
    var result = Zero
    var addend = pt
    var k = n
    while k.signum() > 0 do
      if k.testBit(0) then result = add(result, addend)
      addend = add(addend, addend)
      k = k.shiftRight(1)
    result

  def mulBase(n: BigInteger): Point = mul(n, B)

  def isIdentity(pt: Point): Boolean = pt.x.signum() == 0 && pt.y.equals(BigInteger.ONE)

  /** True iff pt is in the prime-order subgroup (L * pt == identity). */
  def isOnMainSubgroup(pt: Point): Boolean = isIdentity(mul(L, pt))

  // --- Encoding ------------------------------------------------------------

  def encode(pt: Point): Array[Byte] =
    val out = toLittleEndian(pt.y, 32)
    if pt.x.testBit(0) then out(31) = (out(31) | 0x80).toByte // sign bit = x parity
    out

  /** RFC 8032 point decoding. Returns None if the bytes are not a curve point. */
  def decode(bytes: Array[Byte]): Option[Point] =
    if bytes.length != 32 then return None
    val b = bytes.clone()
    val sign = (b(31) & 0x80) >>> 7
    b(31) = (b(31) & 0x7f).toByte
    val y = fromLittleEndian(b)
    if y.compareTo(p) >= 0 then return None // non-canonical y
    recoverX(y, sign).map(x => Point(x, y))

  /** Recover x from y and the sign bit (RFC 8032 §5.1.3). */
  private def recoverX(y: BigInteger, sign: Int): Option[BigInteger] =
    val y2 = m(y, y)
    val u  = y2.subtract(BigInteger.ONE).mod(p)
    val v  = m(d, y2).add(BigInteger.ONE).mod(p)
    val v3 = m(m(v, v), v)
    val v7 = m(m(v3, v3), v)
    var x  = m(m(u, v3), u.multiply(v7).mod(p).modPow(p.subtract(BigInteger.valueOf(5)).divide(BigInteger.valueOf(8)), p))
    val vx2 = m(v, m(x, x))
    if vx2.equals(u) then ()                              // x is a square root
    else if vx2.equals(p.subtract(u).mod(p)) then x = m(x, I) // multiply by sqrt(-1)
    else return None                                     // no square root -> off curve
    if x.signum() == 0 && sign == 1 then return None      // (0, y) with sign 1 is invalid
    if x.testBit(0) != (sign == 1) then x = p.subtract(x).mod(p)
    Some(x)

  private def toLittleEndian(n: BigInteger, len: Int): Array[Byte] =
    val out = new Array[Byte](len)
    var v = n.mod(p)
    var i = 0
    while i < len do
      out(i) = v.and(BigInteger.valueOf(0xff)).intValue.toByte
      v = v.shiftRight(8)
      i += 1
    out

  private def fromLittleEndian(bytes: Array[Byte]): BigInteger =
    var v = BigInteger.ZERO
    var i = bytes.length - 1
    while i >= 0 do
      v = v.shiftLeft(8).or(BigInteger.valueOf((bytes(i) & 0xff).toLong))
      i -= 1
    v

  // --- Scalars (little-endian, mod L) --------------------------------------

  def scalarFromLE(bytes: Array[Byte]): BigInteger = fromLittleEndian(bytes)

  def scalarToLE32(n: BigInteger): Array[Byte] =
    val out = new Array[Byte](32)
    var v = n.mod(L)
    var i = 0
    while i < 32 do
      out(i) = v.and(BigInteger.valueOf(0xff)).intValue.toByte
      v = v.shiftRight(8)
      i += 1
    out

package hearth.crypto

/** Bech32m encoder/decoder (BIP-350). Bech32m is the modern human-readable
  * address format: strong error *detection*, a human-readable prefix, all
  * lowercase, QR-friendly. This is the checksum variant (constant 0x2bc830a3),
  * not the original Bech32 (constant 1).
  */
object Bech32m:

  private val Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
  private val Const   = 0x2bc830a3
  private val Gen     = Array(0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)

  /** Encode a human-readable prefix and payload bytes into a Bech32m string. */
  def encode(hrp: String, data: Array[Byte]): String =
    val values   = convertBits(data.map(_ & 0xff), 8, 5, pad = true)
      .getOrElse(throw new IllegalArgumentException("cannot regroup payload bits"))
    val checksum = createChecksum(hrp, values)
    val sb = new StringBuilder(hrp).append('1')
    (values ++ checksum).foreach(v => sb.append(Charset(v)))
    sb.toString

  /** Verify structure + checksum only, returning the hrp and the raw 5-bit data
    * groups (checksum stripped). This is the Bech32m string-validity layer; it
    * does not require the payload to be byte-aligned.
    */
  def decodeRaw(s: String): Either[String, (String, Array[Int])] =
    if s != s.toLowerCase && s != s.toUpperCase then return Left("mixed-case string")
    val lower = s.toLowerCase
    val pos   = lower.lastIndexOf('1')
    if pos < 1 then return Left("missing or empty human-readable prefix")
    if lower.length - pos - 1 < 6 then return Left("data part too short for checksum")
    val hrp      = lower.substring(0, pos)
    val dataPart = lower.substring(pos + 1)
    val values   = new Array[Int](dataPart.length)
    var i = 0
    while i < dataPart.length do
      val idx = Charset.indexOf(dataPart(i).toInt)
      if idx < 0 then return Left(s"illegal character '${dataPart(i)}'")
      values(i) = idx
      i += 1
    if polymod(hrpExpand(hrp) ++ values) != Const then return Left("bad checksum")
    Right((hrp, values.dropRight(6)))

  /** Decode a Bech32m string into (hrp, payload bytes). Adds byte-alignment on
    * top of [[decodeRaw]] — the form addresses use. Returns Left on any error.
    */
  def decode(s: String): Either[String, (String, Array[Byte])] =
    decodeRaw(s).flatMap { (hrp, values) =>
      convertBits(values, 5, 8, pad = false).map(b => (hrp, b.map(_.toByte)))
        .toRight("payload is not byte-aligned")
    }

  // --- internals -----------------------------------------------------------

  private def polymod(values: Array[Int]): Int =
    var chk = 1
    for v <- values do
      val b = chk >>> 25
      chk = ((chk & 0x1ffffff) << 5) ^ v
      var i = 0
      while i < 5 do
        if ((b >> i) & 1) == 1 then chk ^= Gen(i)
        i += 1
    chk

  private def hrpExpand(hrp: String): Array[Int] =
    hrp.map(c => c.toInt >> 5).toArray ++ Array(0) ++ hrp.map(c => c.toInt & 31).toArray

  private def createChecksum(hrp: String, data: Array[Int]): Array[Int] =
    val values = hrpExpand(hrp) ++ data ++ Array(0, 0, 0, 0, 0, 0)
    val pm     = polymod(values) ^ Const
    (0 until 6).map(i => (pm >> (5 * (5 - i))) & 31).toArray

  /** Regroup a bit stream from `from`-bit groups into `to`-bit groups. */
  private def convertBits(data: Array[Int], from: Int, to: Int, pad: Boolean): Option[Array[Int]] =
    var acc  = 0
    var bits = 0
    val maxv = (1 << to) - 1
    val out  = scala.collection.mutable.ArrayBuffer.empty[Int]
    var ok   = true
    var i    = 0
    while ok && i < data.length do
      val value = data(i)
      if value < 0 || (value >> from) != 0 then ok = false
      else
        acc = (acc << from) | value
        bits += from
        while bits >= to do
          bits -= to
          out += (acc >> bits) & maxv
      i += 1
    if !ok then None
    else if pad then
      if bits > 0 then out += (acc << (to - bits)) & maxv
      Some(out.toArray)
    else if bits >= from || ((acc << (to - bits)) & maxv) != 0 then None
    else Some(out.toArray)

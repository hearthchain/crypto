package hearth.crypto

object Hex:
  def encode(bytes: Array[Byte]): String =
    val sb = new StringBuilder(bytes.length * 2)
    for b <- bytes do sb.append(f"${b & 0xff}%02x")
    sb.toString

  def decode(s: String): Array[Byte] =
    val clean = s.trim.replaceAll("\\s", "")
    require(clean.length % 2 == 0, "hex string must have even length")
    clean.grouped(2).map(h => Integer.parseInt(h, 16).toByte).toArray

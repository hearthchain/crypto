package hearth.crypto

import java.text.Normalizer
import scala.io.Source

/** BIP-39 mnemonic handling: checksum validation and seed derivation.
  *
  * The seed derivation (PBKDF2-HMAC-SHA512, 2048 iterations) is built directly
  * on libsodium's HMAC so the whole pipeline stays on one audited primitive and
  * there is no ambiguity about how the password bytes are encoded (UTF-8, NFKD).
  */
object Bip39:

  private val Iterations = 2048
  private val SeedLen    = 64

  /** The official English wordlist, loaded from resources. */
  lazy val wordlist: Vector[String] =
    val stream = getClass.getResourceAsStream("/bip39/english.txt")
    require(stream != null, "bip39/english.txt resource missing")
    val src = Source.fromInputStream(stream, "UTF-8")
    try src.getLines().map(_.trim).filter(_.nonEmpty).toVector
    finally src.close()

  private lazy val wordIndex: Map[String, Int] = wordlist.zipWithIndex.toMap

  /** Validate the BIP-39 checksum. Returns Left(reason) if invalid. */
  def validate(mnemonic: String)(using b: CryptoBackend): Either[String, Unit] =
    val words = normalize(mnemonic).split(" ").toVector.filter(_.nonEmpty)
    if !Set(12, 15, 18, 21, 24).contains(words.size) then
      return Left(s"word count must be 12/15/18/21/24, got ${words.size}")
    val indices = words.map(w => wordIndex.get(w).toRight(s"unknown word: '$w'"))
    indices.collectFirst { case Left(e) => e } match
      case Some(e) => return Left(e)
      case None    => ()
    val idx = indices.collect { case Right(i) => i }

    // Reassemble the ENT+CS bit string, split, and recompute the checksum.
    val bits = idx.flatMap(i => (10 to 0 by -1).map(b => (i >> b) & 1))
    val totalBits = bits.size
    val csBits    = totalBits / 33
    val entBits   = totalBits - csBits
    val entropy   = bitsToBytes(bits.take(entBits))
    val hash      = b.sha256(entropy)
    val expected  = (0 until csBits).map(i => (hash(i / 8) >> (7 - (i % 8))) & 1)
    val actual    = bits.drop(entBits)
    if expected.toVector != actual then Left("checksum mismatch") else Right(())

  /** Derive the 64-byte BIP-39 seed from a mnemonic and optional passphrase. */
  def toSeed(mnemonic: String, passphrase: String = "")(using b: CryptoBackend): Array[Byte] =
    val password = normalize(mnemonic).getBytes("UTF-8")
    val salt     = normalize("mnemonic" + passphrase).getBytes("UTF-8")
    pbkdf2HmacSha512(password, salt, Iterations, SeedLen)

  private def normalize(s: String): String = Normalizer.normalize(s, Normalizer.Form.NFKD)

  private def bitsToBytes(bits: Vector[Int]): Array[Byte] =
    require(bits.size % 8 == 0)
    bits.grouped(8).map(g => g.foldLeft(0)((acc, b) => (acc << 1) | b).toByte).toArray

  /** PBKDF2 with PRF = HMAC-SHA512, implemented over libsodium's HMAC. */
  private def pbkdf2HmacSha512(password: Array[Byte], salt: Array[Byte], iterations: Int, dkLen: Int)(using b: CryptoBackend): Array[Byte] =
    val hLen   = Crypto.Sha512Bytes
    val blocks = math.ceil(dkLen.toDouble / hLen).toInt
    val dk     = new Array[Byte](blocks * hLen)
    for i <- 1 to blocks do
      val intI = Array[Byte](((i >> 24) & 0xff).toByte, ((i >> 16) & 0xff).toByte, ((i >> 8) & 0xff).toByte, (i & 0xff).toByte)
      var u    = b.hmacSha512(password, salt ++ intI)
      val t    = u.clone()
      var iter = 1
      while iter < iterations do
        u = b.hmacSha512(password, u)
        var j = 0
        while j < hLen do
          t(j) = (t(j) ^ u(j)).toByte
          j += 1
        iter += 1
      System.arraycopy(t, 0, dk, (i - 1) * hLen, hLen)
    dk.take(dkLen)

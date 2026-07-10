package hearth.crypto

/** SLIP-0010 hierarchical key derivation for the ed25519 curve.
  *
  * This is the derivation Ledger devices use for Ed25519 accounts: the derived
  * 32-byte node key IS the Ed25519 seed (which is then hashed+clamped to the
  * scalar). Only hardened derivation exists for ed25519.
  */
object Slip10:

  final case class Node(privateKey: Array[Byte], chainCode: Array[Byte])

  private val Ed25519MasterKey = "ed25519 seed".getBytes("US-ASCII")
  private val Hardened         = 0x80000000

  /** Master node from a BIP-39 (or any) seed. */
  def master(seed: Array[Byte])(using b: CryptoBackend): Node =
    val i = b.hmacSha512(Ed25519MasterKey, seed)
    Node(i.slice(0, 32), i.slice(32, 64))

  /** One hardened child derivation step. `index` is the raw index (the hardened
    * bit is added automatically since ed25519 supports hardened only).
    */
  def deriveChild(parent: Node, index: Int)(using b: CryptoBackend): Node =
    val hardenedIndex = index | Hardened
    val data = Array[Byte](0) ++ parent.privateKey ++ ser32(hardenedIndex)
    val i    = b.hmacSha512(parent.chainCode, data)
    Node(i.slice(0, 32), i.slice(32, 64))

  /** Derive along a path such as "m/44'/9381'/0'/0'/0'". Every level is hardened. */
  def derivePath(seed: Array[Byte], path: String)(using b: CryptoBackend): Node =
    val segments = parsePath(path)
    segments.foldLeft(master(seed))((node, idx) => deriveChild(node, idx))

  def parsePath(path: String): Vector[Int] =
    val trimmed = path.trim
    require(trimmed == "m" || trimmed.startsWith("m/"), s"path must start with 'm': $path")
    if trimmed == "m" then Vector.empty
    else
      trimmed.drop(2).split("/").toVector.map { raw =>
        val cleaned = raw.stripSuffix("'").stripSuffix("h").stripSuffix("H")
        val n = cleaned.toIntOption.getOrElse(throw new IllegalArgumentException(s"bad path segment: '$raw'"))
        require(n >= 0 && (n & Hardened) == 0, s"index out of range: $raw")
        n
      }

  private def ser32(i: Int): Array[Byte] =
    Array[Byte](((i >> 24) & 0xff).toByte, ((i >> 16) & 0xff).toByte, ((i >> 8) & 0xff).toByte, (i & 0xff).toByte)

package hearth.crypto

/** Ed25519 (EdDSA, RFC 8032) keys and signatures — the standard, Ledger-native
  * signature scheme. The same key material also backs the ECVRF (see [[Ecvrf]]).
  *
  * All operations run on a [[CryptoBackend]] (libsodium or pure-JVM), taken as a
  * `using` parameter that defaults to [[Crypto]].
  */
object Ed25519:

  /** An Ed25519 keypair derived from a 32-byte seed.
    *
    *  - `seed`       : the 32-byte SLIP-0010 node key (the RFC 9381 "SK").
    *  - `publicKey`  : 32-byte compressed point Y = x*B.
    *  - `secretKey`  : the 64-byte expanded form (seed || publicKey).
    */
  final case class KeyPair(seed: Array[Byte], publicKey: Array[Byte], secretKey: Array[Byte]):
    def sign(message: Array[Byte])(using b: CryptoBackend): Array[Byte] = b.signDetached(message, secretKey)

  def fromSeed(seed: Array[Byte])(using b: CryptoBackend): KeyPair =
    require(seed.length == 32, "Ed25519 seed must be 32 bytes")
    val (pk, sk) = b.signSeedKeypair(seed)
    KeyPair(seed, pk, sk)

  def verify(signature: Array[Byte], message: Array[Byte], publicKey: Array[Byte])(using b: CryptoBackend): Boolean =
    b.verifyDetached(signature, message, publicKey)

  /** RFC 8032 secret scalar: clamp(SHA-512(seed)[0..32]). Used by ECVRF. */
  private[crypto] def secretScalar(seed: Array[Byte])(using b: CryptoBackend): Array[Byte] =
    val h = b.sha512(seed)
    val a = h.slice(0, 32)
    a(0)  = (a(0) & 0xf8).toByte
    a(31) = ((a(31) & 0x7f) | 0x40).toByte
    a

  /** RFC 8032 nonce prefix: SHA-512(seed)[32..64]. Used by ECVRF nonce gen. */
  private[crypto] def noncePrefix(seed: Array[Byte])(using b: CryptoBackend): Array[Byte] =
    b.sha512(seed).slice(32, 64)

package hearth.crypto

/** ECVRF-EDWARDS25519-SHA512-TAI, the Ed25519 verifiable random function from
  * RFC 9381 (suite_string = 0x03).
  *
  * It reuses the exact Ed25519 key derived from BIP-39/SLIP-0010: the VRF secret
  * scalar is `clamp(SHA-512(seed))` and the VRF public key is the Ed25519 public
  * key. So a single Ledger-derived key both signs (EdDSA) and produces VRF
  * proofs for miner election. Curve/scalar arithmetic runs on a [[CryptoBackend]]
  * (libsodium or pure-JVM), defaulting to [[Crypto]].
  */
object Ecvrf:

  private val Suite: Byte = 0x03
  private val PtLen  = Crypto.PointBytes  // 32
  private val CLen   = 16                 // challenge length in bytes
  private val ProofLen = PtLen + CLen + PtLen // 80
  private val Identity: Array[Byte] = Array[Byte](1) ++ Array.fill(31)(0.toByte)

  /** A VRF proof pi = Gamma(32) || c(16) || s(32). */
  final case class Proof(gamma: Array[Byte], c: Array[Byte], s: Array[Byte]):
    def bytes: Array[Byte] = gamma ++ c ++ s

  /** Prove: returns the proof pi and the VRF output beta (64 bytes). */
  def prove(seed: Array[Byte], alpha: Array[Byte])(using b: CryptoBackend): (Proof, Array[Byte]) =
    val x  = Ed25519.secretScalar(seed)
    val y  = b.scalarmultBaseNoclamp(x) // public key Y = x*B
    val h  = encodeToCurve(y, alpha)
    val gamma = b.scalarmultNoclamp(x, h).getOrElse(sys.error("Gamma = x*H failed"))
    val k  = nonce(seed, h)
    val u  = b.scalarmultBaseNoclamp(k)                        // U = k*B
    val v  = b.scalarmultNoclamp(k, h).getOrElse(sys.error("V = k*H failed")) // V = k*H
    val c  = challenge(y, h, gamma, u, v)                      // 16 bytes
    val c32 = c ++ Array.fill(PtLen - CLen)(0.toByte)
    val s  = b.scalarAdd(k, b.scalarMul(c32, x))               // s = k + c*x mod L
    val proof = Proof(gamma, c, s)
    (proof, proofToHash(proof))

  /** Verify a proof against the public key and alpha. Returns Some(beta) if
    * valid, None otherwise.
    */
  def verify(publicKey: Array[Byte], alpha: Array[Byte], pi: Array[Byte])(using b: CryptoBackend): Option[Array[Byte]] =
    decode(pi).flatMap { proof =>
      val h   = encodeToCurve(publicKey, alpha)
      val c32 = proof.c ++ Array.fill(PtLen - CLen)(0.toByte)
      for
        sB     <- Some(b.scalarmultBaseNoclamp(proof.s))
        cY     <- b.scalarmultNoclamp(c32, publicKey)
        u      <- b.pointSub(sB, cY)                       // U = s*B - c*Y
        sH     <- b.scalarmultNoclamp(proof.s, h)
        cGamma <- b.scalarmultNoclamp(c32, proof.gamma)
        v      <- b.pointSub(sH, cGamma)                   // V = s*H - c*Gamma
        cPrime  = challenge(publicKey, h, proof.gamma, u, v)
        if java.util.Arrays.equals(cPrime, proof.c)
      yield proofToHash(proof)
    }

  /** proof_to_hash: beta = SHA-512(suite || 0x03 || point_to_string(8*Gamma) || 0x00). */
  def proofToHash(proof: Proof)(using b: CryptoBackend): Array[Byte] =
    val gamma8 = cofactorClear(proof.gamma).getOrElse(sys.error("8*Gamma failed"))
    b.sha512(Array(Suite, 0x03.toByte) ++ gamma8 ++ Array(0x00.toByte))

  def decode(pi: Array[Byte]): Option[Proof] =
    if pi.length != ProofLen then None
    else Some(Proof(pi.slice(0, PtLen), pi.slice(PtLen, PtLen + CLen), pi.slice(PtLen + CLen, ProofLen)))

  // --- Internals -----------------------------------------------------------

  /** ECVRF_encode_to_curve_try_and_increment (RFC 9381 §5.4.1.1). */
  private def encodeToCurve(pkString: Array[Byte], alpha: Array[Byte])(using b: CryptoBackend): Array[Byte] =
    var ctr = 0
    var result: Option[Array[Byte]] = None
    while result.isEmpty do
      if ctr > 255 then sys.error("encode_to_curve: no valid point found")
      val hashString = b.sha512(
        Array(Suite, 0x01.toByte) ++ pkString ++ alpha ++ Array(ctr.toByte) ++ Array(0x00.toByte)
      )
      val candidate = hashString.slice(0, PtLen) // string_to_point(first 32 bytes)
      cofactorClear(candidate) match             // INVALID (off-curve) => None => next ctr
        case Some(hp) if !java.util.Arrays.equals(hp, Identity) => result = Some(hp)
        case _                                                   => ()
      ctr += 1
    result.get

  /** Multiply a compressed point by the cofactor 8 via three doublings. Uses
    * point addition, which only requires the point to be on the curve (not on
    * the prime-order subgroup) — exactly what try-and-increment needs. Returns
    * None if the input does not decode to a curve point.
    */
  private def cofactorClear(p: Array[Byte])(using b: CryptoBackend): Option[Array[Byte]] =
    for
      p2 <- b.pointAdd(p, p)
      p4 <- b.pointAdd(p2, p2)
      p8 <- b.pointAdd(p4, p4)
    yield p8

  /** ECVRF_nonce_generation_RFC8032 (RFC 9381 §5.4.2.2). */
  private def nonce(seed: Array[Byte], hString: Array[Byte])(using b: CryptoBackend): Array[Byte] =
    val kString = b.sha512(Ed25519.noncePrefix(seed) ++ hString)
    b.scalarReduce(kString) // k = string_to_int(k_string) mod L

  /** ECVRF_challenge_generation (RFC 9381 §5.4.3): first 16 bytes of
    * SHA-512(suite || 0x02 || Y || H || Gamma || U || V || 0x00).
    */
  private def challenge(y: Array[Byte], h: Array[Byte], gamma: Array[Byte], u: Array[Byte], v: Array[Byte])(using b: CryptoBackend): Array[Byte] =
    b.sha512(Array(Suite, 0x02.toByte) ++ y ++ h ++ gamma ++ u ++ v ++ Array(0x00.toByte)).slice(0, CLen)

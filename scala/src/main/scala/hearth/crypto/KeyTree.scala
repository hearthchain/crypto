package hearth.crypto

/** All of an account's keys, derived from one BIP-39 seed but living in
  * separate per-role / per-curve trees:
  *
  *  - transaction signing (ed25519, SLIP-0010)  role 0
  *  - VRF / miner election (ed25519, SLIP-0010)  role 1  — a DISTINCT scalar
  *  - BLS finality        (BLS12-381, EIP-2333)
  *
  * The signing and VRF keys use different hardened role indices so their secret
  * scalars are unrelated. That removes the EdDSA/ECVRF shared-key risk: with no
  * shared nonce prefix, the cross-protocol nonce-collision attack cannot apply.
  */
object KeyTree:

  private val CoinType = 9381 // placeholder — register a SLIP-0044 value

  private val RoleSigning = 0
  private val RoleVrf     = 1

  /** ed25519 transaction-signing path, e.g. m/44'/9381'/0'/0'/0'. */
  def signingPath(account: Int): String = s"m/44'/$CoinType'/$account'/$RoleSigning'/0'"

  /** ed25519 VRF path, e.g. m/44'/9381'/0'/1'/0'. */
  def vrfPath(account: Int): String = s"m/44'/$CoinType'/$account'/$RoleVrf'/0'"

  /** BLS finality path (EIP-2334), e.g. m/12381/9381/0/0 — no hardened marker. */
  def blsPath(account: Int): String = s"m/${Bls.Purpose}/$CoinType/$account/0"

  /** ed25519 keypair for signing transactions. */
  def signingKey(seed: Array[Byte], account: Int = 0)(using CryptoBackend): Ed25519.KeyPair =
    Ed25519.fromSeed(Slip10.derivePath(seed, signingPath(account)).privateKey)

  /** ed25519 keypair for the VRF. Its `.seed` feeds [[Ecvrf.prove]]; `.publicKey`
    * is the VRF public key to register.
    */
  def vrfKey(seed: Array[Byte], account: Int = 0)(using CryptoBackend): Ed25519.KeyPair =
    Ed25519.fromSeed(Slip10.derivePath(seed, vrfPath(account)).privateKey)

  /** BLS12-381 finality secret key (32-byte big-endian scalar). */
  def blsSecretKey(seed: Array[Byte], account: Int = 0)(using CryptoBackend): Array[Byte] =
    Bls.derivePath(seed, blsPath(account))

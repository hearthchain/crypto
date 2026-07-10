package hearth.crypto

/** Account addresses.
  *
  * Layout: `Bech32m(hrp, versionByte || SHA-256(publicKey)[0..20])`.
  *
  *  - Hashing the key (not using it raw) gives key-type agility via the version
  *    byte and keeps the public key hidden until first spend.
  *  - SHA-256 is used because it is available identically on both crypto
  *    backends, so an address is byte-for-byte reproducible with or without
  *    native libsodium.
  *  - The per-network HRP (`hrtht`/`hrthm`) is a UX guard against sending to the
  *    wrong network. It is NOT replay protection — that belongs in the signed
  *    transaction (network id + nonce), since an attacker replays signed bytes,
  *    not typed addresses.
  */
enum Network(val hrp: String):
  case Testnet extends Network("hrtht")
  case Mainnet extends Network("hrthm")

object Network:
  def byHrp(hrp: String): Option[Network] = values.find(_.hrp == hrp)

/** A decoded address: the network it is for and the 20-byte account hash. */
final case class Address(network: Network, hash: Array[Byte], version: Byte):
  def encoded: String = Bech32m.encode(network.hrp, Array(version) ++ hash)
  override def toString: String = encoded

object Address:
  /** Version byte identifying the account/key scheme. */
  val Ed25519Version: Byte = 0x00
  private val HashLen = 20

  /** Derive the address string for an Ed25519 public key on a given network. */
  def fromPublicKey(publicKey: Array[Byte], network: Network)(using b: CryptoBackend): String =
    require(publicKey.length == 32, "public key must be 32 bytes")
    val hash = b.sha256(publicKey).take(HashLen)
    Bech32m.encode(network.hrp, Array(Ed25519Version) ++ hash)

  /** Parse and validate an address string. */
  def parse(s: String): Either[String, Address] =
    Bech32m.decode(s).flatMap { (hrp, payload) =>
      for
        network <- Network.byHrp(hrp).toRight(s"unknown network prefix '$hrp'")
        _       <- Either.cond(payload.length == HashLen + 1, (), s"bad payload length ${payload.length}")
        _       <- Either.cond(payload(0) == Ed25519Version, (), f"unsupported address version 0x${payload(0)}%02x")
      yield Address(network, payload.drop(1), payload(0))
    }

  /** Parse and require a specific network (rejects cross-network addresses). */
  def parseFor(s: String, expected: Network): Either[String, Address] =
    parse(s).flatMap(a => Either.cond(a.network == expected, a, s"expected ${expected.hrp} address, got ${a.network.hrp}"))

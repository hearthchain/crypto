package hearth

import hearth.crypto.*
import java.math.BigInteger

class BlsSpec extends munit.FunSuite:

  private val backends: List[CryptoBackend] =
    val sodium = try { SodiumBackend.selfTest(); List[CryptoBackend](SodiumBackend) }
                 catch { case _: Throwable => Nil }
    JvmBackend :: sodium

  private def big(sk: Array[Byte]) = new BigInteger(1, sk)

  // EIP-2333 official test vectors (seed hex, master_SK, child_index, child_SK).
  private case class Vec(seed: String, master: String, index: Long, child: String)
  private val vectors = List(
    Vec("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        "6083874454709270928345386274498605044986640685124978867557563392430687146096",
        0L,
        "20397789859736650942317412262472558107875392172444076792671091975210932703118"),
    Vec("3141592653589793238462643383279502884197169399375105820974944592",
        "29757020647961307431480504535336562678282505419141012933316116377660817309383",
        3141592653L,
        "25457201688850691947727629385191704516744796114925897962676248250929345014287"),
    Vec("0099ff991111002299dd7744ee3355bbdd8844115566cc55663355668888cc00",
        "27580842291869792442942448775674722299803720648445448686099262467207037398656",
        4294967295L,
        "29358610794459428860402234341874281240803786294062035874021252734817515685787"),
    Vec("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
        "19022158461524446591288038168518313374041767046816487870552872741050760015818",
        42L,
        "31372231650479070279774297061823572166496564838472787488249775572789064611981")
  )

  for backend <- backends do
    given CryptoBackend = backend
    vectors.zipWithIndex.foreach { (v, i) =>
      test(s"[${backend.name}] EIP-2333 vector ${i} (master + child)") {
        val seed   = Hex.decode(v.seed)
        val master = Bls.deriveMasterSk(seed)
        assertEquals(master.length, 32)
        assertEquals(big(master), new BigInteger(v.master), "master_SK mismatch")
        val child = Bls.deriveChildSk(master, v.index)
        assertEquals(big(child), new BigInteger(v.child), "child_SK mismatch")
      }
    }

  test("EIP-2334 path derivation and hardened-notation rejection") {
    given CryptoBackend = JvmBackend
    val seed = Hex.decode("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
    // m/42 must equal deriveChildSk(master, 42)
    val viaPath  = Bls.derivePath(seed, "m/42")
    val viaSteps = Bls.deriveChildSk(Bls.deriveMasterSk(seed), 42L)
    assertEquals(Hex.encode(viaPath), Hex.encode(viaSteps))
    // a full EIP-2334 path derives without error and stays in range
    assertEquals(Bls.derivePath(seed, "m/12381/9381/0/0").length, 32)
    // apostrophes are an ed25519 concept; reject them for BLS
    intercept[IllegalArgumentException](Bls.parsePath("m/12381/9381/0'/0"))
  }

  test("KeyTree gives signing and VRF keys distinct scalars") {
    given CryptoBackend = JvmBackend
    val seed = Bip39.toSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
    val signing = KeyTree.signingKey(seed)
    val vrf     = KeyTree.vrfKey(seed)
    assertNotEquals(Hex.encode(signing.seed), Hex.encode(vrf.seed))
    assertNotEquals(Hex.encode(signing.publicKey), Hex.encode(vrf.publicKey))
    // signing key path is unchanged from the original single-key design
    assertEquals(KeyTree.signingPath(0), "m/44'/9381'/0'/0'/0'")
    assertEquals(KeyTree.vrfPath(0), "m/44'/9381'/0'/1'/0'")
  }

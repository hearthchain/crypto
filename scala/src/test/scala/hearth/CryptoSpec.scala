package hearth

import hearth.crypto.*
import hearth.crypto.given

class CryptoSpec extends munit.FunSuite:

  private def hex(b: Array[Byte]) = Hex.encode(b)
  private def bytes(s: String)    = Hex.decode(s)

  // Run the crypto-heavy cases on every backend that is available on this host:
  // always the pure-JVM one, plus libsodium when present.
  private val backends: List[CryptoBackend] =
    val sodium = try { SodiumBackend.selfTest(); List[CryptoBackend](SodiumBackend) }
                 catch { case _: Throwable => Nil }
    JvmBackend :: sodium

  test("BIP-39: abandon…about -> known seed (Trezor vector)") {
    val mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    assertEquals(Bip39.validate(mnemonic), Right(()))
    val seed = Bip39.toSeed(mnemonic, "TREZOR")
    assertEquals(
      hex(seed),
      "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
    )
  }

  test("BIP-39: rejects bad checksum") {
    val bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
    assert(Bip39.validate(bad).isLeft)
  }

  test("SLIP-0010 ed25519 test vector 1 (seed 000102…0f)") {
    val seed = bytes("000102030405060708090a0b0c0d0e0f")
    val m    = Slip10.master(seed)
    assertEquals(hex(m.chainCode),  "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb")
    assertEquals(hex(m.privateKey), "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7")
    val m0 = Slip10.derivePath(seed, "m/0'")
    assertEquals(hex(m0.chainCode),  "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69")
    assertEquals(hex(m0.privateKey), "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3")
  }

  // RFC 9381 Appendix B.3, ECVRF-EDWARDS25519-SHA512-TAI
  private case class Vec(sk: String, pk: String, alpha: String, pi: String, beta: String)
  private val rfc9381 = List(
    Vec(
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
      "",
      "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805",
      "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae"
    ),
    Vec(
      "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
      "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
      "72",
      "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02",
      "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031"
    ),
    Vec(
      "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
      "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
      "af82",
      "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e",
      "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f"
    )
  )

  for backend <- backends do
    given CryptoBackend = backend

    rfc9381.zipWithIndex.foreach { (v, i) =>
      test(s"[${backend.name}] RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI vector ${i + 1}") {
        val seed  = bytes(v.sk)
        val alpha = bytes(v.alpha)
        assertEquals(hex(Ed25519.fromSeed(seed).publicKey), v.pk)
        val (proof, beta) = Ecvrf.prove(seed, alpha)
        assertEquals(hex(proof.bytes), v.pi, "pi mismatch")
        assertEquals(hex(beta), v.beta, "beta mismatch")
        val verified = Ecvrf.verify(bytes(v.pk), alpha, bytes(v.pi))
        assert(verified.isDefined, "verify rejected a valid proof")
        assertEquals(hex(verified.get), v.beta)
        assert(Ecvrf.verify(bytes(v.pk), alpha ++ Array(0.toByte), bytes(v.pi)).isEmpty, "verify accepted wrong alpha")
      }
    }

    test(s"[${backend.name}] Ed25519 sign/verify round trip") {
      val kp  = Ed25519.fromSeed(bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
      val msg = "hello hearth".getBytes("UTF-8")
      val sig = kp.sign(msg)
      assert(Ed25519.verify(sig, msg, kp.publicKey))
      assert(!Ed25519.verify(sig, "hello hearthh".getBytes("UTF-8"), kp.publicKey))
    }

  // If both backends exist, they must agree byte-for-byte (drop-in fallback).
  test("libsodium and JVM backends agree (when both present)") {
    if backends.size < 2 then
      println("  (only one backend available; skipping cross-check)")
    else
      val seed  = bytes("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
      val msg   = "cross-backend".getBytes("UTF-8")
      val alpha = "af82ff".getBytes("UTF-8")
      val (pkS, skS) = SodiumBackend.signSeedKeypair(seed)
      val (pkJ, skJ) = JvmBackend.signSeedKeypair(seed)
      assertEquals(hex(pkS), hex(pkJ))
      assertEquals(hex(skS), hex(skJ))
      assertEquals(hex(SodiumBackend.signDetached(msg, skS)), hex(JvmBackend.signDetached(msg, skJ)))
      val (piS, betaS) = Ecvrf.prove(seed, alpha)(using SodiumBackend)
      val (piJ, betaJ) = Ecvrf.prove(seed, alpha)(using JvmBackend)
      assertEquals(hex(piS.bytes), hex(piJ.bytes))
      assertEquals(hex(betaS), hex(betaJ))
      // proof from one verifies under the other
      assert(Ecvrf.verify(pkJ, alpha, piS.bytes)(using JvmBackend).isDefined)
      assert(Ecvrf.verify(pkS, alpha, piJ.bytes)(using SodiumBackend).isDefined)
  }

  // Guard against drift: the embedded wordlist must be the official BIP-39 file.
  test("BIP-39 wordlist matches the official file") {
    val stream = getClass.getResourceAsStream("/bip39/english.txt")
    val data =
      try stream.readAllBytes()
      finally stream.close()
    val digest = java.security.MessageDigest.getInstance("SHA-256").digest(data)
    assertEquals(hex(digest), "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda")
  }

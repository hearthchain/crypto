package hearth

import hearth.crypto.*
import hearth.crypto.given

class AddressSpec extends munit.FunSuite:

  private def hex(b: Array[Byte]) = Hex.encode(b)

  // BIP-350 valid Bech32m strings — the codec must accept all of these.
  private val validBech32m = List(
    "A1LQFN3A",
    "a1lqfn3a",
    "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
    "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
    "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
    "?1v759aa"
  )

  validBech32m.foreach { s =>
    test(s"Bech32m accepts BIP-350 vector: ${s.take(24)}") {
      // These vectors test checksum validity; some payloads are not byte-aligned,
      // so verify at the string/checksum layer (decodeRaw), not the byte layer.
      assert(Bech32m.decodeRaw(s).isRight, s"should decode: $s")
    }
  }

  test("Bech32m rejects a corrupted checksum and mixed case") {
    assert(Bech32m.decodeRaw("a1lqfn3q").isLeft)              // last char flipped
    assert(Bech32m.decodeRaw("A1lqfn3a").isLeft)              // mixed case
    assert(Bech32m.decodeRaw("1lqfn3a").isLeft)               // empty hrp
  }

  test("Bech32m round-trips arbitrary payloads") {
    val payload = Array.tabulate[Byte](21)(i => (i * 7 + 1).toByte)
    val s = Bech32m.encode("hrthm", payload)
    val Right((hrp, back)) = Bech32m.decode(s): @unchecked
    assertEquals(hrp, "hrthm")
    assertEquals(hex(back), hex(payload))
  }

  // Regression: address for the demo public key (059/…0196) on both networks.
  private val demoPk = Hex.decode("058b96bd967c4ad867eaab255dbce080cb1a45d03cf622caf8c16e4d871b0196")

  test("Address derivation is stable (pinned vectors)") {
    assertEquals(Address.fromPublicKey(demoPk, Network.Mainnet), "hrthm1qqh3nv88tllmfh43ldjelfkxn4dw96mmhcj9u36h")
    assertEquals(Address.fromPublicKey(demoPk, Network.Testnet), "hrtht1qqh3nv88tllmfh43ldjelfkxn4dw96mmhcwumd6m")
  }

  test("Address parse recovers network, version and 20-byte hash") {
    val s = Address.fromPublicKey(demoPk, Network.Mainnet)
    val Right(addr) = Address.parse(s): @unchecked
    assertEquals(addr.network, Network.Mainnet)
    assertEquals(addr.version, Address.Ed25519Version)
    assertEquals(addr.hash.length, 20)
    assertEquals(hex(addr.hash), hex(Crypto.sha256(demoPk).take(20)))
  }

  test("Address body is identical across networks; only the prefix differs") {
    val Right(main) = Address.parse(Address.fromPublicKey(demoPk, Network.Mainnet)): @unchecked
    val Right(test) = Address.parse(Address.fromPublicKey(demoPk, Network.Testnet)): @unchecked
    assertEquals(hex(main.hash), hex(test.hash))
  }

  test("parseFor rejects a cross-network address (UX guard, not replay protection)") {
    val mainnet = Address.fromPublicKey(demoPk, Network.Mainnet)
    assert(Address.parseFor(mainnet, Network.Testnet).isLeft)
    assert(Address.parseFor(mainnet, Network.Mainnet).isRight)
  }

  test("Address rejects a tampered string") {
    val s = Address.fromPublicKey(demoPk, Network.Mainnet)
    val tampered = s.updated(s.length - 1, if s.last == 'q' then 'p' else 'q')
    assert(Address.parse(tampered).isLeft)
  }

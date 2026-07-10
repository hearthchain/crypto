package hearth.app

import hearth.crypto.*
import hearth.crypto.given
import java.util.Base64

/** Sample app for the hearth-chain crypto stack.
  *
  * Usage:
  *   sbt "run [mnemonic] [messageBase64] [alphaBase64]"
  *
  * With no arguments it uses a fixed demo mnemonic and sample payloads so the
  * whole pipeline (BIP-39 -> SLIP-0010 -> Ed25519 sign/verify -> ECVRF) runs
  * end to end. Every value is printed in hex/base64 so runs are reproducible.
  */
object Demo:

  // Standard BIP-39 test mnemonic (all-"abandon" 12-word vector).
  private val DefaultMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  private val Account = 0

  def main(args: Array[String]): Unit =
    val mnemonic  = args.lift(0).filter(_.nonEmpty).getOrElse(DefaultMnemonic)
    val messageB64 = args.lift(1).filter(_.nonEmpty).getOrElse(Base64.getEncoder.encodeToString("hearth-chain block header".getBytes("UTF-8")))
    val alphaB64   = args.lift(2).filter(_.nonEmpty).getOrElse(Base64.getEncoder.encodeToString("epoch-42-slot-7".getBytes("UTF-8")))

    section("0) Inputs")
    println(s"crypto backend : ${Crypto.name}")
    println(s"mnemonic       : $mnemonic")
    Bip39.validate(mnemonic) match
      case Right(_) => println("mnemonic check : VALID (BIP-39 checksum ok)")
      case Left(e)  => println(s"mnemonic check : INVALID ($e)"); sys.exit(1)

    // (1) Derive keys — one mnemonic, separate per-role / per-curve trees ----
    section("1) Key derivation (one mnemonic -> distinct signing / VRF / BLS keys)")
    val bip39Seed = Bip39.toSeed(mnemonic)
    val signing   = KeyTree.signingKey(bip39Seed, Account)  // ed25519, SLIP-0010 role 0
    val vrf       = KeyTree.vrfKey(bip39Seed, Account)      // ed25519, SLIP-0010 role 1
    val blsSk     = KeyTree.blsSecretKey(bip39Seed, Account) // BLS12-381, EIP-2333
    println(s"BIP-39 seed    : ${Hex.encode(bip39Seed)}")
    println()
    println(s"signing path   : ${KeyTree.signingPath(Account)}")
    println(s"signing pubkey : ${Hex.encode(signing.publicKey)}")
    println(s"address (main) : ${Address.fromPublicKey(signing.publicKey, Network.Mainnet)}")
    println(s"address (test) : ${Address.fromPublicKey(signing.publicKey, Network.Testnet)}")
    println()
    println(s"VRF path       : ${KeyTree.vrfPath(Account)}")
    println(s"VRF pubkey     : ${Hex.encode(vrf.publicKey)}  (distinct scalar from signing)")
    println()
    println(s"BLS path       : ${KeyTree.blsPath(Account)}  (EIP-2333, no hardened marker)")
    println(s"BLS secret key : ${Hex.encode(blsSk)}  (32-byte scalar mod r)")

    // (2) Sign a base64 message --------------------------------------------
    section("2) Ed25519 sign (RFC 8032, Ledger-native) — signing key")
    val message   = Base64.getDecoder.decode(messageB64)
    val signature = signing.sign(message)
    println(s"message (b64)  : $messageB64")
    println(s"message (hex)  : ${Hex.encode(message)}")
    println(s"signature      : ${Hex.encode(signature)}  (64 bytes)")

    // (3) Verify the signature ---------------------------------------------
    section("3) Ed25519 verify")
    val sigOk = Ed25519.verify(signature, message, signing.publicKey)
    println(s"verify         : ${if sigOk then "VALID" else "INVALID"}")
    val tampered = message.clone(); if tampered.nonEmpty then tampered(0) = (tampered(0) ^ 0x01).toByte
    println(s"verify tampered: ${if Ed25519.verify(signature, tampered, signing.publicKey) then "VALID (!)" else "INVALID (expected)"}")

    // (4) VRF sign and derive VRF value ------------------------------------
    section("4) ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381) — VRF key")
    val alpha        = Base64.getDecoder.decode(alphaB64)
    val (proof, beta) = Ecvrf.prove(vrf.seed, alpha)
    val vrfOk        = Ecvrf.verify(vrf.publicKey, alpha, proof.bytes)
    println(s"alpha (b64)    : $alphaB64")
    println(s"alpha (hex)    : ${Hex.encode(alpha)}")
    println(s"pi (proof)     : ${Hex.encode(proof.bytes)}  (80 bytes)")
    println(s"  gamma        : ${Hex.encode(proof.gamma)}")
    println(s"  c            : ${Hex.encode(proof.c)}")
    println(s"  s            : ${Hex.encode(proof.s)}")
    println(s"beta (VRF out) : ${Hex.encode(beta)}  (64 bytes)")
    println(s"vrf verify     : ${vrfOk.fold("INVALID")(_ => "VALID")}")
    vrfOk.foreach(b => println(s"vrf verify beta: ${Hex.encode(b)}  (matches: ${java.util.Arrays.equals(b, beta)})"))

  private def section(title: String): Unit =
    println()
    println(s"== $title ==")

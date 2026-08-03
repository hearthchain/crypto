package tech.hearth.app;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import tech.hearth.crypto.Address;
import tech.hearth.crypto.Bip39;
import tech.hearth.crypto.Crypto;
import tech.hearth.crypto.Ecvrf;
import tech.hearth.crypto.Ed25519;
import tech.hearth.crypto.Hex;
import tech.hearth.crypto.KeyTree;
import tech.hearth.crypto.SigningKey;
import tech.hearth.crypto.VrfKey;

/**
 * Sample app for the hearth-chain crypto stack. Derives distinct signing / VRF /
 * BLS keys from one mnemonic, signs and verifies a message, then VRF-proves an
 * alpha and derives + verifies the VRF value beta.
 *
 * <p>It uses the no-argument API forms, which resolve {@link Crypto#defaultBackend()}
 * (libsodium if present, else pure JVM). Pass an explicit backend where you need
 * to pin one.
 *
 * <p>Usage: {@code Demo [mnemonic] [messageBase64] [alphaBase64]}
 */
public final class Demo {
    private Demo() {}

    private static final String DEFAULT_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon abandon abandon "
                    + "abandon abandon abandon about";
    private static final int ACCOUNT = 0;

    public static void main(String[] args) {
        String mnemonic = arg(args, 0, DEFAULT_MNEMONIC);
        String messageB64 = arg(args, 1, b64("hearth-chain block header"));
        String alphaB64 = arg(args, 2, b64("epoch-42-slot-7"));

        section("0) Inputs");
        System.out.println("crypto backend : " + Crypto.defaultBackend().name());
        System.out.println("mnemonic       : " + mnemonic);
        if (Bip39.validate(mnemonic) instanceof Bip39.ValidationResult.Invalid(String reason)) {
            System.out.println("mnemonic check : INVALID (" + reason + ")");
            System.exit(1);
        }
        System.out.println("mnemonic check : VALID (BIP-39 checksum ok)");

        // (1) Derive keys — one mnemonic, separate per-role / per-curve trees
        section("1) Key derivation (one mnemonic -> distinct signing / VRF / BLS keys)");
        byte[] seed = Bip39.toSeed(mnemonic);
        SigningKey signing = KeyTree.signingKey(seed, ACCOUNT);
        VrfKey vrf = KeyTree.vrfKey(seed, ACCOUNT);
        byte[] blsSk = KeyTree.blsSecretKey(seed, ACCOUNT);
        System.out.println("BIP-39 seed    : " + Hex.encode(seed));
        System.out.println();
        System.out.println("signing path   : " + KeyTree.signingPath(ACCOUNT));
        System.out.println("signing pubkey : " + Hex.encode(signing.publicKey()));
        Address address = signing.toAddress();
        System.out.println("address (main) : " + address.toBech32(Address.MAINNET_HRP));
        System.out.println("address (test) : " + address.toBech32(Address.TESTNET_HRP));
        System.out.println();
        System.out.println("VRF path       : " + KeyTree.vrfPath(ACCOUNT));
        System.out.println("VRF pubkey     : " + Hex.encode(vrf.publicKey()) + "  (distinct scalar from signing)");
        System.out.println();
        System.out.println("BLS path       : " + KeyTree.blsPath(ACCOUNT) + "  (EIP-2333, no hardened marker)");
        System.out.println("BLS secret key : " + Hex.encode(blsSk) + "  (32-byte scalar mod r)");

        // (2) Sign a base64 message with the signing key
        section("2) Ed25519 sign (RFC 8032, Ledger-native) - signing key");
        byte[] message = Base64.getDecoder().decode(messageB64);
        byte[] signature = signing.sign(message);
        System.out.println("message (b64)  : " + messageB64);
        System.out.println("message (hex)  : " + Hex.encode(message));
        System.out.println("signature      : " + Hex.encode(signature) + "  (64 bytes)");

        // (3) Verify the signature
        section("3) Ed25519 verify");
        System.out.println("verify         : " + (Ed25519.verify(signature, message, signing.publicKey()) ? "VALID" : "INVALID"));
        byte[] tampered = message.clone();
        if (tampered.length > 0) {
            tampered[0] ^= 0x01;
        }
        System.out.println("verify tampered: "
                + (Ed25519.verify(signature, tampered, signing.publicKey()) ? "VALID (!)" : "INVALID (expected)"));

        // (4) VRF sign and derive VRF value with the VRF key
        section("4) ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381) - VRF key");
        byte[] alpha = Base64.getDecoder().decode(alphaB64);
        Ecvrf.ProveResult result = Ecvrf.prove(vrf, alpha);
        var vrfOk = Ecvrf.verify(vrf.publicKey(), alpha, result.proof().bytes());
        System.out.println("alpha (b64)    : " + alphaB64);
        System.out.println("alpha (hex)    : " + Hex.encode(alpha));
        System.out.println("pi (proof)     : " + Hex.encode(result.proof().bytes()) + "  (80 bytes)");
        System.out.println("  gamma        : " + Hex.encode(result.proof().gamma()));
        System.out.println("  c            : " + Hex.encode(result.proof().c()));
        System.out.println("  s            : " + Hex.encode(result.proof().s()));
        System.out.println("beta (VRF out) : " + Hex.encode(result.beta()) + "  (64 bytes)");
        System.out.println("vrf verify     : " + (vrfOk.isPresent() ? "VALID" : "INVALID"));
        vrfOk.ifPresent(b -> System.out.println(
                "vrf verify beta: " + Hex.encode(b) + "  (matches: " + Arrays.equals(b, result.beta()) + ")"));
    }

    private static void section(String title) {
        System.out.println();
        System.out.println("== " + title + " ==");
    }

    private static String arg(String[] args, int i, String fallback) {
        return (i < args.length && !args[i].isEmpty()) ? args[i] : fallback;
    }

    private static String b64(String s) {
        return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }
}

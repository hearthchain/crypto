package tech.hearth.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class CryptoVectorsTest {

    private static final String ABANDON =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    private static byte[] hx(String s) {
        return Hex.decode(s);
    }

    private static String hex(byte[] b) {
        return Hex.encode(b);
    }

    /** JVM backend always; libsodium when present. */
    static Stream<Named<CryptoBackend>> backends() {
        List<Named<CryptoBackend>> list = new ArrayList<>();
        list.add(Named.of("jvm", JvmBackend.INSTANCE));
        try {
            SodiumBackend sodium = new SodiumBackend();
            sodium.selfTest();
            list.add(Named.of("libsodium", sodium));
        } catch (Throwable ignored) {
            // libsodium not available
        }
        return list.stream();
    }

    private static CryptoBackend anyBackend() {
        return Crypto.defaultBackend();
    }

    // --- BIP-39 ----------------------------------------------------------

    @Test
    void bip39TrezorSeed() {
        CryptoBackend b = anyBackend();
        assertTrue(Bip39.validate(ABANDON, b).isValid());
        assertEquals(
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
                hex(Bip39.toSeed(ABANDON, "TREZOR", b)));
    }

    @Test
    void bip39RejectsBadChecksum() {
        String bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        Bip39.ValidationResult result = Bip39.validate(bad, anyBackend());
        assertFalse(result.isValid());
        assertEquals("checksum mismatch", ((Bip39.ValidationResult.Invalid) result).reason());
    }

    // --- SLIP-0010 -------------------------------------------------------

    @Test
    void slip10Ed25519Vector1() {
        CryptoBackend b = anyBackend();
        byte[] seed = hx("000102030405060708090a0b0c0d0e0f");
        Slip10.Node m = Slip10.master(seed, b);
        assertEquals("90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb", hex(m.chainCode()));
        assertEquals("2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7", hex(m.privateKey()));
        Slip10.Node m0 = Slip10.derivePath(seed, "m/0'", b);
        assertEquals("8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69", hex(m0.chainCode()));
        assertEquals("68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3", hex(m0.privateKey()));
    }

    // --- RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI --------------------------

    private record Vec(String sk, String pk, String alpha, String pi, String beta) {}

    private static final List<Vec> RFC9381 = List.of(
            new Vec("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                    "",
                    "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805",
                    "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae"),
            new Vec("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                    "72",
                    "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02",
                    "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031"),
            new Vec("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                    "af82",
                    "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e",
                    "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f"));

    @ParameterizedTest
    @MethodSource("backends")
    void rfc9381(CryptoBackend b) {
        for (Vec v : RFC9381) {
            byte[] seed = hx(v.sk);
            byte[] alpha = hx(v.alpha);
            assertEquals(v.pk, hex(VrfKey.fromSeed(seed, b).publicKey()), "pubkey");
            Ecvrf.ProveResult result = Ecvrf.prove(VrfKey.fromSeed(seed, b), alpha, b);
            assertEquals(v.pi, hex(result.proof().bytes()), "pi");
            assertEquals(v.beta, hex(result.beta()), "beta");
            Optional<byte[]> verified = Ecvrf.verify(hx(v.pk), alpha, hx(v.pi), b);
            assertTrue(verified.isPresent(), "verify rejected a valid proof");
            assertEquals(v.beta, hex(verified.get()));
            byte[] wrongAlpha = new byte[alpha.length + 1];
            System.arraycopy(alpha, 0, wrongAlpha, 0, alpha.length);
            assertTrue(Ecvrf.verify(hx(v.pk), wrongAlpha, hx(v.pi), b).isEmpty(), "verify accepted wrong alpha");
        }
    }

    @ParameterizedTest
    @MethodSource("backends")
    void ed25519SignVerify(CryptoBackend b) {
        SigningKey kp = SigningKey.fromSeed(hx("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"), b);
        byte[] msg = "hello hearth".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] sig = kp.sign(msg, b);
        assertTrue(Ed25519.verify(sig, msg, kp.publicKey(), b));
        assertFalse(Ed25519.verify(sig, "hello hearthh".getBytes(java.nio.charset.StandardCharsets.UTF_8), kp.publicKey(), b));
    }

    // --- EIP-2333 --------------------------------------------------------

    private record BlsVec(String seed, String master, long index, String child) {}

    private static final List<BlsVec> EIP2333 = List.of(
            new BlsVec("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
                    "6083874454709270928345386274498605044986640685124978867557563392430687146096", 0,
                    "20397789859736650942317412262472558107875392172444076792671091975210932703118"),
            new BlsVec("3141592653589793238462643383279502884197169399375105820974944592",
                    "29757020647961307431480504535336562678282505419141012933316116377660817309383", 3141592653L,
                    "25457201688850691947727629385191704516744796114925897962676248250929345014287"),
            new BlsVec("0099ff991111002299dd7744ee3355bbdd8844115566cc55663355668888cc00",
                    "27580842291869792442942448775674722299803720648445448686099262467207037398656", 4294967295L,
                    "29358610794459428860402234341874281240803786294062035874021252734817515685787"),
            new BlsVec("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
                    "19022158461524446591288038168518313374041767046816487870552872741050760015818", 42,
                    "31372231650479070279774297061823572166496564838472787488249775572789064611981"));

    @ParameterizedTest
    @MethodSource("backends")
    void eip2333(CryptoBackend b) {
        for (BlsVec v : EIP2333) {
            byte[] master = Bls.deriveMasterSK(hx(v.seed), b);
            assertEquals(32, master.length);
            assertEquals(v.master, new BigInteger(1, master).toString(), "master_SK");
            byte[] child = Bls.deriveChildSK(master, v.index, b);
            assertEquals(v.child, new BigInteger(1, child).toString(), "child_SK");
        }
    }

    @Test
    void eip2334PathAndHardenedRejection() {
        CryptoBackend b = anyBackend();
        byte[] seed = hx("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3");
        assertEquals(hex(Bls.deriveChildSK(Bls.deriveMasterSK(seed, b), 42, b)), hex(Bls.derivePath(seed, "m/42", b)));
        assertEquals(32, Bls.derivePath(seed, "m/12381/9381/0/0", b).length);
        assertTrue(assertThrowsIllegalArg(() -> Bls.parsePath("m/12381/9381/0'/0")));
    }

    // --- Bech32m / Address ----------------------------------------------

    @Test
    void bech32mVectors() {
        String[] valid = {
                "A1LQFN3A", "a1lqfn3a",
                "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
                "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
                "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
                "?1v759aa"};
        for (String s : valid) {
            assertTrue(Bech32m.decodeRaw(s).isPresent(), "should decode: " + s);
        }
        for (String s : new String[]{"a1lqfn3q", "A1lqfn3a", "1lqfn3a"}) {
            assertTrue(Bech32m.decodeRaw(s).isEmpty(), "should reject: " + s);
        }
    }

    private static final String DEMO_PK = "058b96bd967c4ad867eaab255dbce080cb1a45d03cf622caf8c16e4d871b0196";

    @Test
    void addressPinned() {
        CryptoBackend b = anyBackend();
        Address a = Address.fromPublicKey(hx(DEMO_PK), b);
        // one identity, rendered per network via the HRP.
        assertEquals("hrth19uvmpe6ll76dav0mvk06d35att3wk7a7gm8xwm", a.toBech32(Address.MAINNET_HRP));
        assertEquals("thrth19uvmpe6ll76dav0mvk06d35att3wk7a7vvkkh7", a.toBech32(Address.TESTNET_HRP));
        // parse requires the HRP to match the requested one.
        assertEquals(a, Address.parse(a.toBech32(Address.MAINNET_HRP), Address.MAINNET_HRP).orElseThrow());
        assertTrue(Address.parse(a.toBech32(Address.MAINNET_HRP), Address.TESTNET_HRP).isEmpty());
        assertEquals(Address.MAINNET_HRP, Address.hrpOf(a.toBech32(Address.MAINNET_HRP)).orElseThrow());
    }

    @Test
    void addressBytesRoundTripAndValueSemantics() {
        Address a = Address.fromPublicKey(hx(DEMO_PK), anyBackend());

        // 20-byte on-chain form: SHA-256(publicKey)[0:20], round-trips.
        byte[] payload = a.toBytes();
        assertEquals(Address.HASH_LEN, payload.length);
        assertEquals(a, Address.fromBytes(payload).orElseThrow());

        // network-independent identity: same account on any network is the same Address,
        // but its bech32m strings differ.
        Address same = Address.fromBytes(payload.clone()).orElseThrow();
        assertEquals(a, same);
        assertEquals(a.hashCode(), same.hashCode());
        assertNotEquals(a.toBech32(Address.MAINNET_HRP), a.toBech32(Address.TESTNET_HRP));

        // malformed payloads (wrong length) are rejected.
        assertTrue(Address.fromBytes(new byte[19]).isEmpty());
        assertTrue(Address.fromBytes(new byte[21]).isEmpty());
    }

    @Test
    void signingKeyToAddressAndDefaultHrp() {
        SigningKey key = SigningKey.fromSeed(hx("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
        Address addr = key.toAddress(); // network-free identity
        assertEquals(Address.fromPublicKey(key.publicKey()), addr);

        // no-arg toBech32() uses the process-wide default HRP.
        Address.setDefaultHrp(Address.TESTNET_HRP);
        assertEquals(addr.toBech32(Address.TESTNET_HRP), addr.toBech32());
        Address.setDefaultHrp(Address.MAINNET_HRP);
        assertEquals(addr.toBech32(Address.MAINNET_HRP), addr.toBech32());

        // fail-closed when the default is unset.
        Address.setDefaultHrp(null);
        assertThrows(IllegalStateException.class, addr::toBech32);
        Address.setDefaultHrp(Address.MAINNET_HRP);
    }

    @Test
    void defaultHrpAcceptsCustomPrefixes() {
        Address a = Address.fromPublicKey(hx(DEMO_PK), anyBackend());
        try {
            // any well-formed prefix (e.g. a devnet's) renders and round-trips.
            String s = a.toBech32("hrthdev");
            assertTrue(s.startsWith("hrthdev1"));
            assertEquals(a, Address.parse(s, "hrthdev").orElseThrow());
            assertEquals("hrthdev", Address.hrpOf(s).orElseThrow());

            // a foreign prefix does not parse under the requested HRP.
            assertTrue(Address.parse(a.toBech32(Address.MAINNET_HRP), "hrthdev").isEmpty());

            // installing it as the default drives the no-arg helper.
            Address.setDefaultHrp("hrthdev");
            assertEquals("hrthdev", Address.defaultHrp());
            assertEquals(s, a.toBech32());

            // HRPs are normalized (trimmed + lowercased).
            Address.setDefaultHrp("  HRTHDEV  ");
            assertEquals("hrthdev", Address.defaultHrp());

            // invalid prefixes are rejected up front.
            assertThrows(IllegalArgumentException.class, () -> Address.setDefaultHrp(""));
            assertThrows(IllegalArgumentException.class, () -> Address.setDefaultHrp("de1v"));
            assertThrows(IllegalArgumentException.class, () -> a.toBech32("de1v"));
        } finally {
            Address.setDefaultHrp(Address.MAINNET_HRP);
        }
    }

    // --- Cross-parity with the Scala/Python/Go builds --------------------

    @Test
    void crossParity() {
        CryptoBackend b = anyBackend();
        byte[] seed = Bip39.toSeed(ABANDON, "", b);
        assertEquals(
                "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
                hex(seed));
        SigningKey signing = KeyTree.signingKey(seed, 0, b);
        VrfKey vrf = KeyTree.vrfKey(seed, 0, b);
        byte[] blsSk = KeyTree.blsSecretKey(seed, 0, b);
        assertEquals("058b96bd967c4ad867eaab255dbce080cb1a45d03cf622caf8c16e4d871b0196", hex(signing.publicKey()));
        assertEquals("06bc4b2bde1b328430ba118192c21980f4a9e7f424ad1fa31604a977c8d31657", hex(vrf.publicKey()));
        assertEquals("28d0b232f19982772fd2fd9b22be335f2b76fd7a0d455a959a37465d38d089f1", hex(blsSk));
        assertNotEquals(hex(signing.publicKey()), hex(vrf.publicKey()));
        assertEquals("m/44'/9381'/0'/0'/0'", KeyTree.signingPath(0));
        assertEquals("m/44'/9381'/0'/1'/0'", KeyTree.vrfPath(0));
    }

    @Test
    void backendsAgreeWhenBothPresent() {
        List<Named<CryptoBackend>> all = backends().toList();
        if (all.size() < 2) {
            return; // only one backend available
        }
        CryptoBackend jvm = JvmBackend.INSTANCE;
        CryptoBackend sodium = all.stream().map(Named::getPayload).filter(x -> x != jvm).findFirst().orElseThrow();
        byte[] seed = hx("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
        byte[] msg = "cross-backend".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] alpha = "af82ff".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        assertArrayEquals(sodium.signSeedKeypair(seed).publicKey(), jvm.signSeedKeypair(seed).publicKey());
        byte[] sk = jvm.signSeedKeypair(seed).secretKey();
        assertArrayEquals(sodium.signDetached(msg, sk), jvm.signDetached(msg, sk));
        Ecvrf.ProveResult rS = Ecvrf.prove(VrfKey.fromSeed(seed, sodium), alpha, sodium);
        Ecvrf.ProveResult rJ = Ecvrf.prove(VrfKey.fromSeed(seed, jvm), alpha, jvm);
        assertArrayEquals(rS.proof().bytes(), rJ.proof().bytes());
        assertArrayEquals(rS.beta(), rJ.beta());
    }

    // Guard against drift: the embedded wordlist must be the official BIP-39 file.
    @Test
    void wordlistMatchesOfficialBip39() throws Exception {
        byte[] data;
        try (var in = CryptoVectorsTest.class.getResourceAsStream("/bip39/english.txt")) {
            data = in.readAllBytes();
        }
        byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(data);
        assertEquals("2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda", hex(digest));
    }

    private static boolean assertThrowsIllegalArg(Runnable r) {
        try {
            r.run();
            return false;
        } catch (IllegalArgumentException e) {
            return true;
        }
    }
}

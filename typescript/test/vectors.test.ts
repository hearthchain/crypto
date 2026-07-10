// Official test vectors + cross-parity with the Scala/Java/Python/Go/Rust builds.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { sha256 } from "@noble/hashes/sha2.js";
import { address, bech32m, bip39, bls, ecvrf, ed25519, hex, keytree, slip10 } from "../src/index.ts";

const ABANDON =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const hx = (s: string): Uint8Array => hex.decode(s);
const bigDec = (b: Uint8Array): string => (b.length ? BigInt("0x" + hex.encode(b)) : 0n).toString();

test("BIP-39: abandon…about -> Trezor seed", () => {
  assert.equal(bip39.validate(ABANDON).valid, true);
  assert.equal(
    hex.encode(bip39.toSeed(ABANDON, "TREZOR")),
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
  );
});

test("BIP-39: rejects bad checksum", () => {
  const bad =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
  const r = bip39.validate(bad);
  assert.equal(r.valid, false);
  assert.equal(r.valid === false && r.reason, "checksum mismatch");
});

test("SLIP-0010 ed25519 test vector 1", () => {
  const seed = hx("000102030405060708090a0b0c0d0e0f");
  const m = slip10.master(seed);
  assert.equal(hex.encode(m.chainCode), "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb");
  assert.equal(hex.encode(m.privateKey), "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7");
  const m0 = slip10.derivePath(seed, "m/0'");
  assert.equal(hex.encode(m0.chainCode), "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69");
  assert.equal(hex.encode(m0.privateKey), "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3");
});

const RFC9381: Array<[string, string, string, string, string]> = [
  [
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "",
    "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805",
    "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae",
  ],
  [
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    "72",
    "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02",
    "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031",
  ],
  [
    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    "af82",
    "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e",
    "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f",
  ],
];

test("RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI", () => {
  for (const [sk, pk, alpha, pi, beta] of RFC9381) {
    const seed = hx(sk);
    const a = hx(alpha);
    assert.equal(hex.encode(ed25519.KeyPair.fromSeed(seed).publicKey), pk);
    const { proof, beta: betaOut } = ecvrf.prove(seed, a);
    assert.equal(hex.encode(proof.bytes()), pi, "pi");
    assert.equal(hex.encode(betaOut), beta, "beta");
    const verified = ecvrf.verify(hx(pk), a, hx(pi));
    assert.ok(verified, "verify rejected a valid proof");
    assert.equal(hex.encode(verified), beta);
    const wrongAlpha = new Uint8Array([...a, 0]);
    assert.equal(ecvrf.verify(hx(pk), wrongAlpha, hx(pi)), null, "verify accepted wrong alpha");
  }
});

test("Ed25519 sign/verify round trip", () => {
  const kp = ed25519.KeyPair.fromSeed(hx("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
  const msg = new TextEncoder().encode("hello hearth");
  const sig = kp.sign(msg);
  assert.ok(ed25519.verify(sig, msg, kp.publicKey));
  assert.ok(!ed25519.verify(sig, new TextEncoder().encode("hello hearthh"), kp.publicKey));
});

const EIP2333: Array<[string, string, number, string]> = [
  ["c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04", "6083874454709270928345386274498605044986640685124978867557563392430687146096", 0, "20397789859736650942317412262472558107875392172444076792671091975210932703118"],
  ["3141592653589793238462643383279502884197169399375105820974944592", "29757020647961307431480504535336562678282505419141012933316116377660817309383", 3141592653, "25457201688850691947727629385191704516744796114925897962676248250929345014287"],
  ["0099ff991111002299dd7744ee3355bbdd8844115566cc55663355668888cc00", "27580842291869792442942448775674722299803720648445448686099262467207037398656", 4294967295, "29358610794459428860402234341874281240803786294062035874021252734817515685787"],
  ["d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3", "19022158461524446591288038168518313374041767046816487870552872741050760015818", 42, "31372231650479070279774297061823572166496564838472787488249775572789064611981"],
];

test("EIP-2333 BLS12-381 key derivation", () => {
  for (const [seed, master, index, child] of EIP2333) {
    const masterSk = bls.deriveMasterSk(hx(seed));
    assert.equal(masterSk.length, 32);
    assert.equal(bigDec(masterSk), master, "master_SK");
    assert.equal(bigDec(bls.deriveChildSk(masterSk, index)), child, "child_SK");
  }
});

test("EIP-2334 path derivation and hardened-notation rejection", () => {
  const seed = hx("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3");
  assert.equal(hex.encode(bls.derivePath(seed, "m/42")), hex.encode(bls.deriveChildSk(bls.deriveMasterSk(seed), 42)));
  assert.equal(bls.derivePath(seed, "m/12381/9381/0/0").length, 32);
  assert.throws(() => bls.parsePath("m/12381/9381/0'/0"));
});

test("Bech32m BIP-350 vectors", () => {
  const valid = [
    "A1LQFN3A",
    "a1lqfn3a",
    "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
    "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
    "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
    "?1v759aa",
  ];
  for (const s of valid) {
    assert.ok(bech32m.decodeRaw(s), `should decode: ${s}`);
  }
  for (const s of ["a1lqfn3q", "A1lqfn3a", "1lqfn3a"]) {
    assert.equal(bech32m.decodeRaw(s), null, `should reject: ${s}`);
  }
});

const DEMO_PK = "058b96bd967c4ad867eaab255dbce080cb1a45d03cf622caf8c16e4d871b0196";

test("Address pinned + parse", () => {
  const pk = hx(DEMO_PK);
  assert.equal(address.fromPublicKey(pk, address.Network.Mainnet), "hrthm1qqh3nv88tllmfh43ldjelfkxn4dw96mmhcj9u36h");
  assert.equal(address.fromPublicKey(pk, address.Network.Testnet), "hrtht1qqh3nv88tllmfh43ldjelfkxn4dw96mmhcwumd6m");
  const main = address.fromPublicKey(pk, address.Network.Mainnet);
  const parsed = address.parse(main);
  assert.ok(parsed);
  assert.equal(parsed.network, address.Network.Mainnet);
  assert.equal(parsed.hash.length, 20);
  assert.equal(address.parseFor(main, address.Network.Testnet), null);
});

test("Cross-parity with the Scala/Java/Python/Go/Rust builds", () => {
  const seed = bip39.toSeed(ABANDON, "");
  assert.equal(
    hex.encode(seed),
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
  );
  const signing = keytree.signingKey(seed, 0);
  const vrf = keytree.vrfKey(seed, 0);
  const blsSk = keytree.blsSecretKey(seed, 0);
  assert.equal(hex.encode(signing.publicKey), "058b96bd967c4ad867eaab255dbce080cb1a45d03cf622caf8c16e4d871b0196");
  assert.equal(hex.encode(vrf.publicKey), "06bc4b2bde1b328430ba118192c21980f4a9e7f424ad1fa31604a977c8d31657");
  assert.equal(hex.encode(blsSk), "28d0b232f19982772fd2fd9b22be335f2b76fd7a0d455a959a37465d38d089f1");
  assert.notEqual(hex.encode(signing.publicKey), hex.encode(vrf.publicKey));
  assert.equal(keytree.signingPath(0), "m/44'/9381'/0'/0'/0'");
  assert.equal(keytree.vrfPath(0), "m/44'/9381'/0'/1'/0'");
});

test("BIP-39 wordlist matches the official file", () => {
  const embedded = readFileSync(new URL("../src/english.txt", import.meta.url));
  assert.equal(hex.encode(sha256(embedded)), "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda");
});

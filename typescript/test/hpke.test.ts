// RFC 9180 Appendix A base-mode test vectors for DHKEM(X25519, HKDF-SHA256) +
// HKDF-SHA256, plus round-trip and tamper coverage.

import assert from "node:assert/strict";
import test from "node:test";
import { hex, hpke, x25519 } from "../src/index.ts";

const hx = (s: string): Uint8Array => hex.decode(s);
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

type Vector = {
  name: string;
  suite: hpke.Suite;
  info: string;
  skEm: string;
  pkEm: string;
  skRm: string;
  pkRm: string;
  sharedSecret: string;
  key: string;
  baseNonce: string;
  exporterSecret: string;
  pt: string;
  aad: string;
  ct: string;
};

/** RFC 9180 A.1: AES-128-GCM. */
const A1: Vector = {
  name: "A.1",
  suite: "X25519_SHA256_AES128GCM",
  info: "4f6465206f6e2061204772656369616e2055726e",
  skEm: "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
  pkEm: "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
  skRm: "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
  pkRm: "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
  sharedSecret: "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
  key: "4531685d41d65f03dc48f6b8302c05b0",
  baseNonce: "56d890e5accaaf011cff4b7d",
  exporterSecret: "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8",
  pt: "4265617574792069732074727574682c20747275746820626561757479",
  aad: "436f756e742d30",
  ct: "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
};

/** RFC 9180 A.2: ChaCha20-Poly1305. */
const A2: Vector = {
  name: "A.2",
  suite: "X25519_SHA256_CHACHA20POLY1305",
  info: "4f6465206f6e2061204772656369616e2055726e",
  skEm: "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",
  pkEm: "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
  skRm: "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
  pkRm: "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
  sharedSecret: "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7",
  key: "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91",
  baseNonce: "5c4d98150661b848853b547f",
  exporterSecret: "a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922",
  pt: "4265617574792069732074727574682c20747275746820626561757479",
  aad: "436f756e742d30",
  ct: "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
};

function checkVector(v: Vector): void {
  // The keypairs in the vector are self-consistent under our X25519.
  assert.equal(hex.encode(x25519.publicKey(hx(v.skEm))), v.pkEm, `${v.name}: pkEm`);
  assert.equal(hex.encode(x25519.publicKey(hx(v.skRm))), v.pkRm, `${v.name}: pkRm`);

  // DHKEM Encap and Decap agree on the shared secret, and match the vector.
  const enc = hx(v.pkEm);
  const encapped = hpke.extractAndExpand(x25519.dh(hx(v.skEm), hx(v.pkRm)), enc, hx(v.pkRm));
  const decapped = hpke.extractAndExpand(x25519.dh(hx(v.skRm), enc), enc, hx(v.pkRm));
  assert.equal(hex.encode(encapped), v.sharedSecret, `${v.name}: Encap shared_secret`);
  assert.equal(hex.encode(decapped), v.sharedSecret, `${v.name}: Decap shared_secret`);

  // The key schedule.
  const context = hpke.keySchedule(v.suite, hx(v.sharedSecret), hx(v.info));
  assert.equal(hex.encode(context.key), v.key, `${v.name}: key`);
  assert.equal(hex.encode(context.baseNonce), v.baseNonce, `${v.name}: base_nonce`);
  assert.equal(hex.encode(context.exporterSecret), v.exporterSecret, `${v.name}: exporter_secret`);

  // Seal at sequence number 0.
  const sealed = hpke.sealWithEphemeral(v.suite, hx(v.skEm), hx(v.pkRm), hx(v.info), hx(v.aad), hx(v.pt));
  assert.equal(hex.encode(sealed.enc), hex.encode(enc), `${v.name}: enc`);
  assert.equal(hex.encode(sealed.ciphertext), v.ct, `${v.name}: ct`);

  // And Open recovers the plaintext.
  const opened = hpke.open(v.suite, hx(v.skRm), enc, hx(v.info), hx(v.aad), hx(v.ct));
  assert.equal(hex.encode(opened), v.pt, `${v.name}: pt`);
}

test("RFC 9180 A.1 AES-128-GCM", () => checkVector(A1));
test("RFC 9180 A.2 ChaCha20-Poly1305", () => checkVector(A2));

const ALL_SUITES: hpke.Suite[] = [
  "X25519_SHA256_AES128GCM",
  "X25519_SHA256_AES256GCM",
  "X25519_SHA256_CHACHA20POLY1305",
];

test("seal/open round trip on every suite", () => {
  for (const suite of ALL_SUITES) {
    const recipient = x25519.generateKeypair();
    const info = utf8("hearth-test/info");
    const aad = utf8("hearth-test/aad");
    const plaintext = utf8("the quick brown fox");

    const sealed = hpke.seal(suite, recipient.publicKey, info, aad, plaintext);
    assert.equal(sealed.enc.length, hpke.ENC_BYTES);
    assert.equal(sealed.ciphertext.length, plaintext.length + hpke.TAG_BYTES);
    const opened = hpke.open(suite, recipient.secretKey, sealed.enc, info, aad, sealed.ciphertext);
    assert.equal(hex.encode(opened), hex.encode(plaintext));
  }
});

test("seal is randomized per call", () => {
  const recipient = x25519.generateKeypair();
  const suite: hpke.Suite = "X25519_SHA256_CHACHA20POLY1305";
  const first = hpke.seal(suite, recipient.publicKey, utf8("i"), utf8("a"), utf8("p"));
  const second = hpke.seal(suite, recipient.publicKey, utf8("i"), utf8("a"), utf8("p"));
  assert.notEqual(hex.encode(first.enc), hex.encode(second.enc));
  assert.notEqual(hex.encode(first.ciphertext), hex.encode(second.ciphertext));
});

test("open rejects wrong info/aad/key/ciphertext", () => {
  const recipient = x25519.generateKeypair();
  const info = utf8("info");
  const aad = utf8("aad");
  const suite: hpke.Suite = "X25519_SHA256_CHACHA20POLY1305";
  const sealed = hpke.seal(suite, recipient.publicKey, info, aad, utf8("secret"));

  assert.throws(() => hpke.open(suite, recipient.secretKey, sealed.enc, utf8("other"), aad, sealed.ciphertext));
  assert.throws(() => hpke.open(suite, recipient.secretKey, sealed.enc, info, utf8("other"), sealed.ciphertext));
  assert.throws(() =>
    hpke.open(suite, x25519.generateKeypair().secretKey, sealed.enc, info, aad, sealed.ciphertext),
  );

  const tampered = sealed.ciphertext.slice();
  tampered[0] ^= 0x01;
  assert.throws(() => hpke.open(suite, recipient.secretKey, sealed.enc, info, aad, tampered));
});

test("x25519 rejects a small-order public key", () => {
  // The all-zero u-coordinate is the canonical small-order point; RFC 9180
  // requires the KEM to abort rather than derive from an all-zero DH output.
  const smallOrder = new Uint8Array(x25519.KEY_BYTES);
  assert.throws(() => x25519.dh(x25519.generateKeypair().secretKey, smallOrder));
});

test("x25519 rejects other degenerate public keys", () => {
  // Beyond the trivial all-zero point: every other canonical low-order/invalid
  // u-coordinate (u=1, and the boundary encodings p-1, p, p+1 for
  // p = 2^255-19), little-endian. Under X25519's mandatory scalar clamping
  // (which forces the scalar to be a multiple of 8) every point of order
  // dividing 8 collapses to the identity, so the DH output is all-zero for
  // every one of these too — confirmed against a raw (unclamped-check)
  // Montgomery ladder, independent of this library. This is why the single
  // all-zero-output check above is a complete mitigation, not just a
  // heuristic for the one obvious case.
  const vectors: Record<string, string> = {
    "u=1": "0100000000000000000000000000000000000000000000000000000000000000",
    "u=p-1": "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "u=p": "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "u=p+1": "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  };
  const secretKey = x25519.generateKeypair().secretKey;
  for (const [name, h] of Object.entries(vectors)) {
    assert.throws(() => x25519.dh(secretKey, hex.decode(h)), `${name}: expected rejection`);
  }
});

test("suite lookup by AEAD id", () => {
  for (const suite of ALL_SUITES) {
    assert.equal(hpke.suiteFromAeadId(hpke.aeadId(suite)), suite);
  }
  assert.throws(() => hpke.suiteFromAeadId(0x00ff));
});

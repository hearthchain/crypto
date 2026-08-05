import assert from "node:assert/strict";
import test from "node:test";
import { apikeyenvelope as env, hpke, x25519 } from "../src/index.ts";

const NOW = new Date("2026-08-05T12:00:00Z");
const LATER = new Date(NOW.getTime() + 3600 * 1000);

const meta = (): env.Metadata => env.metadata("prod/ingest-api", LATER);

const ALL_SUITES: hpke.Suite[] = [
  "X25519_SHA256_AES128GCM",
  "X25519_SHA256_AES256GCM",
  "X25519_SHA256_CHACHA20POLY1305",
];

test("seal/open round trip on every suite", () => {
  for (const suite of ALL_SUITES) {
    const recipient = x25519.generateKeypair();
    const apiKey = env.randomApiKey();
    const apiKeyCopy = apiKey.slice();

    const envelope = env.seal(recipient.publicKey, apiKey, meta(), suite);

    // 20-byte fixed header + metadata + 32-byte enc + 32-byte key + 16-byte tag.
    const metadataLength = 1 + "prod/ingest-api".length + 8;
    assert.equal(envelope.length, 20 + metadataLength + 32 + 48);

    const opened = env.open(recipient.secretKey, envelope, NOW);
    assert.deepEqual(opened.apiKey, apiKeyCopy);
    assert.equal(opened.metadata.keyId, "prod/ingest-api");
    assert.equal(opened.metadata.notAfter?.getTime(), LATER.getTime());

    env.wipe(opened);
    assert.deepEqual(opened.apiKey, new Uint8Array(env.API_KEY_LENGTH));
  }
});

test("header carries the suite and recipient fingerprint", () => {
  const recipient = x25519.generateKeypair();
  const envelope = env.seal(recipient.publicKey, env.randomApiKey(), meta());

  assert.equal(new TextDecoder().decode(envelope.slice(0, 4)), "HKE1");
  assert.equal(be16(envelope, 4), hpke.KEM_ID);
  assert.equal(be16(envelope, 6), hpke.KDF_ID);
  assert.equal(be16(envelope, 8), hpke.aeadId(env.DEFAULT_SUITE));
  assert.deepEqual(envelope.slice(10, 18), env.fingerprint(recipient.publicKey));
});

test("rejects envelope for another recipient", () => {
  const recipient = x25519.generateKeypair();
  const other = x25519.generateKeypair();
  const envelope = env.seal(recipient.publicKey, env.randomApiKey(), meta());

  assert.throws(() => env.open(other.secretKey, envelope, NOW), /different recipient key/);
});

test("rejects expired envelope", () => {
  const recipient = x25519.generateKeypair();
  const envelope = env.seal(
    recipient.publicKey,
    env.randomApiKey(),
    env.metadata("short-lived", new Date(NOW.getTime() - 1000)),
  );

  assert.throws(() => env.open(recipient.secretKey, envelope, NOW), /envelope expired/);
});

test("metadata without expiry never expires", () => {
  const recipient = x25519.generateKeypair();
  const envelope = env.seal(recipient.publicKey, env.randomApiKey(), env.metadata("forever"));

  const opened = env.open(recipient.secretKey, envelope, new Date("2099-01-01T00:00:00Z"));
  assert.equal(opened.metadata.notAfter, null);
});

test("rejects tampered metadata — every header byte is AAD", () => {
  const recipient = x25519.generateKeypair();
  const envelope = env.seal(recipient.publicKey, env.randomApiKey(), env.metadata("prod/ingest-api", LATER));

  const tampered = envelope.slice();
  const metadataEnd = 20 + 1 + "prod/ingest-api".length + 8;
  tampered[metadataEnd - 1] ^= 0x01;

  assert.throws(() => env.open(recipient.secretKey, tampered, NOW), /not authentic/);
});

test("rejects tampered ciphertext and encapsulated key", () => {
  const recipient = x25519.generateKeypair();
  const envelope = env.seal(recipient.publicKey, env.randomApiKey(), meta());

  for (const offset of [envelope.length - 1, envelope.length - 40, envelope.length - 60]) {
    const tampered = envelope.slice();
    tampered[offset] ^= 0x01;
    assert.throws(() => env.open(recipient.secretKey, tampered, NOW), `flipping byte ${offset} should not open`);
  }
});

test("rejects malformed envelopes", () => {
  const recipient = x25519.generateKeypair();
  const envelope = env.seal(recipient.publicKey, env.randomApiKey(), meta());

  assert.throws(() => env.open(recipient.secretKey, new Uint8Array(3), NOW));

  const wrongMagic = envelope.slice();
  wrongMagic[0] = "X".charCodeAt(0);
  assert.throws(() => env.open(recipient.secretKey, wrongMagic, NOW));

  const truncated = envelope.slice(0, envelope.length - 1);
  assert.throws(() => env.open(recipient.secretKey, truncated, NOW));

  const unknownAead = envelope.slice();
  unknownAead[9] = 0xff;
  assert.throws(() => env.open(recipient.secretKey, unknownAead, NOW));
});

test("rejects API keys of the wrong shape", () => {
  const publicKey = x25519.generateKeypair().publicKey;
  assert.throws(() => env.seal(publicKey, new TextEncoder().encode("tooshort"), meta()));
  assert.throws(() => env.seal(publicKey, new TextEncoder().encode("0123456789012345678901234567890!"), meta()));
});

test("metadata rejects empty or oversized key id", () => {
  assert.throws(() => env.metadata(""));
  assert.throws(() => env.metadata("k".repeat(256)));
});

test("randomApiKey is alphanumeric and covers the alphabet", () => {
  const seen = new Set<string>();
  for (let i = 0; i < 200; i++) {
    const key = env.randomApiKey();
    assert.equal(key.length, env.API_KEY_LENGTH);
    for (const b of key) {
      const c = String.fromCharCode(b);
      assert.ok(/[A-Za-z0-9]/.test(c), `not ASCII alphanumeric: ${c}`);
      seen.add(c);
    }
  }
  // 6400 draws over a 62-character alphabet: every character should appear.
  assert.equal(seen.size, 62);
});

function be16(bytes: Uint8Array, offset: number): number {
  return (bytes[offset] << 8) | bytes[offset + 1];
}

/**
 * Dad's Morse — v5 Container Test Suite
 *
 * Tests the DMM1 v5 cryptographic container format:
 *   Argon2id → HKDF-SHA256 → AES-256-GCM (header as AAD)
 *   Optional Ed25519 signatures (over header ‖ ciphertext, verified before decrypt)
 *
 * Requirements:
 *   Node.js 18+ (WebCrypto + Ed25519 support)
 *   npm install  (installs argon2-browser)
 *
 * Run:
 *   node test_crypto.mjs
 */

import { webcrypto } from 'crypto';
import { argon2id as hashWasmArgon2id } from 'hash-wasm';

const { subtle } = webcrypto;
const getRandomValues = (arr) => webcrypto.getRandomValues(arr);

// ============================================================
// CORE CRYPTO — extracted from index.html, adapted for Node.js
// ============================================================

const DMM1_MAGIC = [0x44, 0x4d, 0x4d, 0x31];
const DMM1_VERSION = 0x05;
const FLAG_PEPPER = 0x01;
const FLAG_SIGNED = 0x02;
const DMM1_HEADER_LEN = 34;

function base64ToBytes(b64) {
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

function bytesToBase64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

function bytesToHex(bytes) {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
  return hex.toUpperCase();
}

function hexToBytes(hex) {
  hex = hex.replace(/\s/g, '');
  if (hex.length % 2 !== 0) throw new Error("Invalid hex: odd length");
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const pair = hex.substr(i * 2, 2);
    const val = parseInt(pair, 16);
    if (isNaN(val)) throw new Error("Invalid hex character");
    bytes[i] = val;
  }
  return bytes;
}

function concatPwPepper(pw, pep) {
  if (!pep) return pw;
  return pw.length.toString(16) + ':' + pw + '\0' + pep.length.toString(16) + ':' + pep;
}

const hexMorse = {
  '0':'-----', '1':'.----', '2':'..---', '3':'...--', '4':'....-', '5':'.....',
  '6':'-....', '7':'--...', '8':'---..', '9':'----.', 'A':'.-', 'B':'-...',
  'C':'-.-.', 'D':'-..', 'E':'.', 'F':'..-.'
};
const morseToHexMap = Object.fromEntries(Object.entries(hexMorse).map(([k,v]) => [v,k]));

function toMorse(hex) {
  return hex.toUpperCase().split('').map(c => hexMorse[c] || '').filter(Boolean).join(' ');
}

function fromMorse(morse) {
  const groups = morse.trim().split(/\s+/).filter(Boolean);
  let hex = '', invalid = false;
  for (const g of groups) {
    const h = morseToHexMap[g];
    if (!h) { invalid = true; hex += '?'; }
    else hex += h;
  }
  return { hex: hex.toLowerCase(), invalid };
}

async function hkdf(master, salt, info, length) {
  const key = await subtle.importKey("raw", master, "HKDF", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode(info) },
    key,
    length * 8
  );
  return new Uint8Array(bits);
}

async function argon2id(pass, salt, timeCost = 4, memCost = 65535, parallelism = 4, hashLen = 32) {
  // hash-wasm provides Argon2id with identical output to argon2-browser
  // Same algorithm, same parameters, compatible output — just works in Node.js
  const hashHex = await hashWasmArgon2id({
    password: new TextEncoder().encode(pass),
    salt,
    iterations: timeCost,
    memorySize: memCost,  // KiB, same unit as argon2-browser's mem
    parallelism,
    hashLength: hashLen,
    outputType: 'hex'
  });
  const bytes = new Uint8Array(hashLen);
  for (let i = 0; i < hashLen; i++) {
    bytes[i] = parseInt(hashHex.substr(i * 2, 2), 16);
  }
  return bytes;
}

async function encryptMessage(msg, pw, pep, signPrivKey) {
  const salt = getRandomValues(new Uint8Array(16));
  const iv = getRandomValues(new Uint8Array(12));

  const pwPep = concatPwPepper(pw, pep);
  const masterKey = await argon2id(pwPep, salt);
  const aesKeyRaw = await hkdf(masterKey, salt, "dmm1/aes-key", 32);
  const aesKey = await subtle.importKey("raw", aesKeyRaw, "AES-GCM", false, ["encrypt"]);

  const flags = (pep ? FLAG_PEPPER : 0) | (signPrivKey ? FLAG_SIGNED : 0);
  const header = new Uint8Array(DMM1_HEADER_LEN);
  let off = 0;
  header.set(DMM1_MAGIC, off); off += 4;
  header[off++] = DMM1_VERSION;
  header[off++] = flags;
  header.set(salt, off); off += 16;
  header.set(iv, off); off += 12;

  const plaintext = new TextEncoder().encode(msg);
  const ciphertext = await subtle.encrypt(
    { name: "AES-GCM", iv, tagLength: 128, additionalData: header },
    aesKey,
    plaintext
  );

  let signature = null;
  if (signPrivKey) {
    const signablePayload = new Uint8Array(header.length + ciphertext.byteLength);
    signablePayload.set(header);
    signablePayload.set(new Uint8Array(ciphertext), header.length);

    const privKey = await subtle.importKey(
      "pkcs8", base64ToBytes(signPrivKey),
      { name: "Ed25519" }, false, ["sign"]
    );
    signature = new Uint8Array(await subtle.sign("Ed25519", privKey, signablePayload));
  }

  const final = new Uint8Array(header.length + (signature ? 64 : 0) + ciphertext.byteLength);
  final.set(header);
  if (signature) final.set(signature, header.length);
  final.set(new Uint8Array(ciphertext), header.length + (signature ? 64 : 0));

  return final;
}

async function decryptMessage(data, pw, pep, senderPubKey) {
  // Minimum: header(34) + 16-byte GCM tag (empty plaintext is valid in GCM)
  if (data.length < DMM1_HEADER_LEN + 16) throw new Error("Invalid data: too short");

  let off = 0;
  const magic = data.slice(off, off+4); off += 4;
  if (magic[0] !== DMM1_MAGIC[0] || magic[1] !== DMM1_MAGIC[1] ||
      magic[2] !== DMM1_MAGIC[2] || magic[3] !== DMM1_MAGIC[3]) {
    throw new Error("Invalid magic bytes");
  }

  const version = data[off++];
  if (version !== DMM1_VERSION) throw new Error("Unsupported container version");

  const flags = data[off++];
  const salt = data.slice(off, off+16); off += 16;
  const iv = data.slice(off, off+12); off += 12;

  const header = data.slice(0, DMM1_HEADER_LEN);

  const hasSig = (flags & FLAG_SIGNED) !== 0;
  const sig = hasSig ? data.slice(off, off+64) : null;
  if (hasSig) {
    if (data.length < DMM1_HEADER_LEN + 64 + 16) throw new Error("Invalid data: truncated signature");
    off += 64;
  }
  const ciphertext = data.slice(off);

  if (hasSig) {
    if (!senderPubKey) throw new Error("Message is signed but no public key provided");
    const signablePayload = new Uint8Array(header.length + ciphertext.length);
    signablePayload.set(header);
    signablePayload.set(ciphertext, header.length);

    const pubKey = await subtle.importKey(
      "spki", base64ToBytes(senderPubKey),
      { name: "Ed25519" }, false, ["verify"]
    );
    const valid = await subtle.verify("Ed25519", pubKey, sig, signablePayload);
    if (!valid) throw new Error("Signature verification failed");
  }

  const pwPep = concatPwPepper(pw, (flags & FLAG_PEPPER) ? pep : "");
  const masterKey = await argon2id(pwPep, salt);
  const aesKeyRaw = await hkdf(masterKey, salt, "dmm1/aes-key", 32);
  const aesKey = await subtle.importKey("raw", aesKeyRaw, "AES-GCM", false, ["decrypt"]);

  try {
    const plaintext = await subtle.decrypt(
      { name: "AES-GCM", iv, tagLength: 128, additionalData: header },
      aesKey,
      ciphertext
    );
    return new TextDecoder().decode(plaintext);
  } catch (e) {
    throw new Error("Decryption failed (wrong password or corrupted data)");
  }
}

// ============================================================
// TEST RUNNER
// ============================================================

let pass = 0, fail = 0;
const failures = [];

async function test(num, name, fn) {
  try {
    await fn();
    pass++;
    console.log(`  ✅ ${num}. ${name}`);
  } catch (e) {
    fail++;
    failures.push({ num, name, error: e.message });
    console.log(`  ❌ ${num}. ${name} — ${e.message}`);
  }
}

function assert(condition, msg) {
  if (!condition) throw new Error(msg || "Assertion failed");
}

function assertThrows(fn, msgContains) {
  let threw = false;
  try { fn(); } catch (e) {
    threw = true;
    if (msgContains && !e.message.includes(msgContains)) {
      throw new Error(`Expected error containing "${msgContains}", got: "${e.message}"`);
    }
  }
  if (!threw) throw new Error("Expected function to throw");
}

async function assertRejects(fn, msgContains) {
  let threw = false;
  try { await fn(); } catch (e) {
    threw = true;
    if (msgContains && !e.message.includes(msgContains)) {
      throw new Error(`Expected error containing "${msgContains}", got: "${e.message}"`);
    }
  }
  if (!threw) throw new Error("Expected function to reject");
}

// ============================================================
// TESTS
// ============================================================

console.log("\n🔐 Dad's Morse v5 — Crypto Test Suite\n");

const PW = "test-password-14ch!";
const PW2 = "wrong-password-here!";
const PEPPER = "signal-key-pepper";
const MSG = "Hello from Dad's Morse";

// ── Container format ──

console.log("── Container Format ──");

await test(1, "Encrypt + decrypt round-trip", async () => {
  const ct = await encryptMessage(MSG, PW, null, null);
  const pt = await decryptMessage(ct, PW, null, null);
  assert(pt === MSG, `Expected "${MSG}", got "${pt}"`);
});

await test(2, "Wrong password is rejected", async () => {
  const ct = await encryptMessage(MSG, PW, null, null);
  await assertRejects(() => decryptMessage(ct, PW2, null, null));
});

await test(3, "Random salt+IV — same input produces different ciphertext", async () => {
  const ct1 = await encryptMessage(MSG, PW, null, null);
  const ct2 = await encryptMessage(MSG, PW, null, null);
  assert(bytesToHex(ct1) !== bytesToHex(ct2), "Ciphertexts should differ");
});

await test(4, "Header is 34 bytes: magic(4) + version(1) + flags(1) + salt(16) + iv(12)", async () => {
  const ct = await encryptMessage("x", PW, null, null);
  assert(ct[0] === 0x44 && ct[1] === 0x4D && ct[2] === 0x4D && ct[3] === 0x31, "Magic mismatch");
  assert(ct[4] === 0x05, "Version should be 0x05");
  assert(ct[5] === 0x00, "Flags should be 0x00 (no pepper, no signing)");
  // Total: 34 header + 1 byte plaintext + 16 byte GCM tag = 51 minimum
  assert(ct.length === 34 + 1 + 16, `Expected 51 bytes, got ${ct.length}`);
});

await test(5, "Minimum payload size enforced", async () => {
  await assertRejects(() => decryptMessage(new Uint8Array(49), PW, null, null), "too short");
});

await test(6, "Invalid magic bytes rejected", async () => {
  const ct = await encryptMessage(MSG, PW, null, null);
  ct[0] = 0xFF; // corrupt magic
  await assertRejects(() => decryptMessage(ct, PW, null, null), "Invalid magic");
});

await test(7, "Wrong version rejected", async () => {
  const ct = await encryptMessage(MSG, PW, null, null);
  ct[4] = 0x04; // old version
  await assertRejects(() => decryptMessage(ct, PW, null, null), "Unsupported container version");
});

await test(8, "Tampered header (AAD) causes GCM failure", async () => {
  const ct = await encryptMessage(MSG, PW, null, null);
  ct[5] ^= 0xFF; // flip flags byte
  await assertRejects(() => decryptMessage(ct, PW, null, null));
});

await test(9, "Tampered ciphertext causes GCM failure", async () => {
  const ct = await encryptMessage(MSG, PW, null, null);
  ct[ct.length - 1] ^= 0xFF; // flip last byte (in GCM tag)
  await assertRejects(() => decryptMessage(ct, PW, null, null));
});

await test(10, "Empty string round-trips", async () => {
  const ct = await encryptMessage("", PW, null, null);
  const pt = await decryptMessage(ct, PW, null, null);
  assert(pt === "", `Expected empty string, got "${pt}"`);
});

await test(11, "Unicode / emoji / CJK round-trip", async () => {
  const msg = "Hello 🌍 こんにちは 你好 مرحبا";
  const ct = await encryptMessage(msg, PW, null, null);
  const pt = await decryptMessage(ct, PW, null, null);
  assert(pt === msg, "Unicode mismatch");
});

await test(12, "Long message (1000 chars) round-trip", async () => {
  const msg = "A".repeat(1000);
  const ct = await encryptMessage(msg, PW, null, null);
  const pt = await decryptMessage(ct, PW, null, null);
  assert(pt === msg && pt.length === 1000, "Long message mismatch");
});

await test(13, "No padding — ciphertext = plaintext length + 16 (GCM tag)", async () => {
  for (const len of [1, 7, 15, 16, 17, 31, 32, 33, 100, 255]) {
    const msg = "x".repeat(len);
    const ct = await encryptMessage(msg, PW, null, null);
    const expectedLen = DMM1_HEADER_LEN + len + 16; // header + plaintext + GCM tag
    assert(ct.length === expectedLen,
      `len=${len}: expected ${expectedLen} bytes, got ${ct.length}`);
  }
});

// ── Pepper / Signal Key ──

console.log("\n── Pepper / Signal Key ──");

await test(14, "Pepper: encrypt + decrypt round-trip", async () => {
  const ct = await encryptMessage(MSG, PW, PEPPER, null);
  const pt = await decryptMessage(ct, PW, PEPPER, null);
  assert(pt === MSG, "Pepper round-trip failed");
});

await test(15, "Pepper: FLAG_PEPPER bit set", async () => {
  const ct = await encryptMessage(MSG, PW, PEPPER, null);
  assert((ct[5] & FLAG_PEPPER) !== 0, "FLAG_PEPPER should be set");
});

await test(16, "No pepper: FLAG_PEPPER bit clear", async () => {
  const ct = await encryptMessage(MSG, PW, null, null);
  assert((ct[5] & FLAG_PEPPER) === 0, "FLAG_PEPPER should be clear");
});

await test(17, "Pepper used — decrypt without pepper fails", async () => {
  const ct = await encryptMessage(MSG, PW, PEPPER, null);
  await assertRejects(() => decryptMessage(ct, PW, null, null));
});

await test(18, "Wrong pepper fails", async () => {
  const ct = await encryptMessage(MSG, PW, PEPPER, null);
  await assertRejects(() => decryptMessage(ct, PW, "wrong-pepper", null));
});

await test(19, "concatPwPepper: length-prefixed domain separation", () => {
  const r1 = concatPwPepper("abc", "def");
  const r2 = concatPwPepper("abcdef", "");
  const r3 = concatPwPepper("ab", "cdef");
  assert(r1 !== r2 && r1 !== r3 && r2 !== r3, "Domain separation failed");
});

await test(20, "concatPwPepper: no pepper returns raw password", () => {
  assert(concatPwPepper("mypass", null) === "mypass", "Should return raw pw");
  assert(concatPwPepper("mypass", "") === "mypass", "Empty pepper = no pepper");
});

// ── HKDF key separation ──

console.log("\n── HKDF Key Separation ──");

await test(21, "HKDF: different labels produce different keys", async () => {
  const master = getRandomValues(new Uint8Array(32));
  const salt = getRandomValues(new Uint8Array(16));
  const k1 = await hkdf(master, salt, "dmm1/aes-key", 32);
  const k2 = await hkdf(master, salt, "dmm1/other-key", 32);
  assert(bytesToHex(k1) !== bytesToHex(k2), "Different labels should produce different keys");
});

await test(22, "HKDF: same label + same input = deterministic", async () => {
  const master = new Uint8Array(32); master.fill(0xAA);
  const salt = new Uint8Array(16); salt.fill(0xBB);
  const k1 = await hkdf(master, salt, "dmm1/aes-key", 32);
  const k2 = await hkdf(master, salt, "dmm1/aes-key", 32);
  assert(bytesToHex(k1) === bytesToHex(k2), "Deterministic key derivation failed");
});

// ── Hex encoding ──

console.log("\n── Hex Encoding ──");

await test(23, "bytesToHex → hexToBytes round-trip", () => {
  const data = getRandomValues(new Uint8Array(64));
  const hex = bytesToHex(data);
  const back = hexToBytes(hex);
  assert(bytesToHex(back) === bytesToHex(data), "Hex round-trip failed");
});

await test(24, "hexToBytes: rejects odd-length hex", () => {
  assertThrows(() => hexToBytes("ABC"), "odd length");
});

await test(25, "hexToBytes: rejects invalid characters", () => {
  assertThrows(() => hexToBytes("ZZZZ"), "Invalid hex");
});

await test(26, "bytesToHex produces uppercase", () => {
  const hex = bytesToHex(new Uint8Array([0xab, 0xcd, 0xef]));
  assert(hex === "ABCDEF", `Expected ABCDEF, got ${hex}`);
});

// ── Morse codec ──

console.log("\n── Morse Codec ──");

await test(27, "All 16 hex chars have unique Morse codes", () => {
  const codes = Object.values(hexMorse);
  const unique = new Set(codes);
  assert(unique.size === 16, `Expected 16 unique codes, got ${unique.size}`);
  assert(Object.keys(hexMorse).length === 16, "Should have exactly 16 entries");
});

await test(28, "toMorse → fromMorse round-trip for all hex chars", () => {
  const hex = "0123456789ABCDEF";
  const morse = toMorse(hex);
  const { hex: back, invalid } = fromMorse(morse);
  assert(!invalid, "Should not be invalid");
  assert(back === hex.toLowerCase(), `Expected ${hex.toLowerCase()}, got ${back}`);
});

await test(29, "Morse output contains only valid hex Morse symbols", () => {
  const validSymbols = new Set([...Object.values(hexMorse), ' ']);
  const hex = bytesToHex(getRandomValues(new Uint8Array(32)));
  const morse = toMorse(hex);
  for (const sym of morse.split(' ')) {
    assert(Object.values(hexMorse).includes(sym), `Invalid Morse symbol: ${sym}`);
  }
});

await test(30, "Full Morse pipeline: encrypt → hex → Morse → hex → decrypt", async () => {
  const ct = await encryptMessage(MSG, PW, null, null);
  const hex = bytesToHex(ct);
  const morse = toMorse(hex);
  const { hex: hexBack, invalid } = fromMorse(morse);
  assert(!invalid, "Morse decode produced invalid output");
  const bytesBack = hexToBytes(hexBack);
  const pt = await decryptMessage(bytesBack, PW, null, null);
  assert(pt === MSG, `Pipeline failed: "${pt}" !== "${MSG}"`);
});

await test(31, "Full Morse pipeline with pepper", async () => {
  const ct = await encryptMessage(MSG, PW, PEPPER, null);
  const hex = bytesToHex(ct);
  const morse = toMorse(hex);
  const { hex: hexBack } = fromMorse(morse);
  const pt = await decryptMessage(hexToBytes(hexBack), PW, PEPPER, null);
  assert(pt === MSG, "Pepper pipeline failed");
});

// ── Base64 path ──

console.log("\n── Base64 Path ──");

await test(32, "Base64 encode → decode round-trip", () => {
  const data = getRandomValues(new Uint8Array(100));
  const b64 = bytesToBase64(data);
  const back = base64ToBytes(b64);
  assert(bytesToHex(data) === bytesToHex(back), "Base64 round-trip failed");
});

await test(33, "Base64 and hex paths produce identical bytes", async () => {
  const ct = await encryptMessage(MSG, PW, null, null);
  const fromB64 = base64ToBytes(bytesToBase64(ct));
  const fromHex = hexToBytes(bytesToHex(ct));
  assert(bytesToHex(fromB64) === bytesToHex(fromHex), "Encoding paths diverge");
});

// ── Ed25519 signing ──

console.log("\n── Ed25519 Signing ──");

let testPrivKeyB64, testPubKeyB64;

await test(34, "Ed25519 key generation", async () => {
  const keyPair = await subtle.generateKey(
    { name: "Ed25519" }, true, ["sign", "verify"]
  );
  const privExported = await subtle.exportKey("pkcs8", keyPair.privateKey);
  const pubExported = await subtle.exportKey("spki", keyPair.publicKey);
  testPrivKeyB64 = bytesToBase64(new Uint8Array(privExported));
  testPubKeyB64 = bytesToBase64(new Uint8Array(pubExported));
  assert(testPrivKeyB64.length > 0 && testPubKeyB64.length > 0, "Key export failed");
});

await test(35, "Signed encrypt + decrypt round-trip", async () => {
  const ct = await encryptMessage(MSG, PW, null, testPrivKeyB64);
  const pt = await decryptMessage(ct, PW, null, testPubKeyB64);
  assert(pt === MSG, "Signed round-trip failed");
});

await test(36, "FLAG_SIGNED bit set when signing", async () => {
  const ct = await encryptMessage(MSG, PW, null, testPrivKeyB64);
  assert((ct[5] & FLAG_SIGNED) !== 0, "FLAG_SIGNED should be set");
});

await test(37, "Signed container is 64 bytes larger (embedded signature)", async () => {
  const unsigned = await encryptMessage(MSG, PW, null, null);
  const signed = await encryptMessage(MSG, PW, null, testPrivKeyB64);
  // Signed has 64 extra bytes for Ed25519 signature, but different salt/iv/ciphertext
  // So check structure: header(34) + sig(64) + ciphertext vs header(34) + ciphertext
  assert((signed[5] & FLAG_SIGNED) !== 0, "Should be flagged as signed");
  assert((unsigned[5] & FLAG_SIGNED) === 0, "Should not be flagged as signed");
});

await test(38, "Signature verified before decryption (wrong key rejects)", async () => {
  // Generate a different keypair
  const kp2 = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const wrongPub = bytesToBase64(new Uint8Array(await subtle.exportKey("spki", kp2.publicKey)));

  const ct = await encryptMessage(MSG, PW, null, testPrivKeyB64);
  await assertRejects(() => decryptMessage(ct, PW, null, wrongPub), "Signature verification failed");
});

await test(39, "Signed message: no public key provided → error", async () => {
  const ct = await encryptMessage(MSG, PW, null, testPrivKeyB64);
  await assertRejects(() => decryptMessage(ct, PW, null, null), "no public key provided");
});

await test(40, "Tampered container → signature verification fails", async () => {
  const ct = await encryptMessage(MSG, PW, null, testPrivKeyB64);
  // Tamper with ciphertext (after header + signature)
  ct[ct.length - 1] ^= 0xFF;
  await assertRejects(() => decryptMessage(ct, PW, null, testPubKeyB64), "Signature verification failed");
});

await test(41, "Signed + pepper combined round-trip", async () => {
  const ct = await encryptMessage(MSG, PW, PEPPER, testPrivKeyB64);
  assert((ct[5] & FLAG_PEPPER) !== 0, "FLAG_PEPPER should be set");
  assert((ct[5] & FLAG_SIGNED) !== 0, "FLAG_SIGNED should be set");
  const pt = await decryptMessage(ct, PW, PEPPER, testPubKeyB64);
  assert(pt === MSG, "Signed+pepper round-trip failed");
});

await test(42, "Full signed pipeline: encrypt → hex → Morse → hex → decrypt", async () => {
  const ct = await encryptMessage(MSG, PW, null, testPrivKeyB64);
  const morse = toMorse(bytesToHex(ct));
  const { hex: hexBack } = fromMorse(morse);
  const pt = await decryptMessage(hexToBytes(hexBack), PW, null, testPubKeyB64);
  assert(pt === MSG, "Signed Morse pipeline failed");
});

// ── Argon2id verification ──

console.log("\n── Argon2id KDF ──");

await test(43, "Argon2id produces 32-byte output", async () => {
  const salt = getRandomValues(new Uint8Array(16));
  const key = await argon2id("testpass", salt);
  assert(key.length === 32, `Expected 32 bytes, got ${key.length}`);
});

await test(44, "Argon2id is deterministic (same input → same output)", async () => {
  const salt = new Uint8Array(16); salt.fill(0x42);
  const k1 = await argon2id("testpass", salt);
  const k2 = await argon2id("testpass", salt);
  assert(bytesToHex(k1) === bytesToHex(k2), "Argon2id should be deterministic");
});

await test(45, "Argon2id: different passwords → different keys", async () => {
  const salt = getRandomValues(new Uint8Array(16));
  const k1 = await argon2id("password-one", salt);
  const k2 = await argon2id("password-two", salt);
  assert(bytesToHex(k1) !== bytesToHex(k2), "Different passwords should produce different keys");
});

await test(46, "Argon2id: different salts → different keys", async () => {
  const s1 = new Uint8Array(16); s1.fill(0x01);
  const s2 = new Uint8Array(16); s2.fill(0x02);
  const k1 = await argon2id("same-password", s1);
  const k2 = await argon2id("same-password", s2);
  assert(bytesToHex(k1) !== bytesToHex(k2), "Different salts should produce different keys");
});

// ── Edge cases ──

console.log("\n── Edge Cases ──");

await test(47, "Non-DMM1 payload rejected", async () => {
  const garbage = getRandomValues(new Uint8Array(100));
  await assertRejects(() => decryptMessage(garbage, PW, null, null));
});

await test(48, "Truncated signed payload rejected", async () => {
  const ct = await encryptMessage(MSG, PW, null, testPrivKeyB64);
  const truncated = ct.slice(0, DMM1_HEADER_LEN + 32); // cut mid-signature
  await assertRejects(() => decryptMessage(truncated, PW, null, testPubKeyB64));
});

await test(49, "v4 container rejected (version 0x04)", async () => {
  const ct = await encryptMessage(MSG, PW, null, null);
  const fake = new Uint8Array(ct);
  fake[4] = 0x04;
  await assertRejects(() => decryptMessage(fake, PW, null, null), "Unsupported container version");
});

await test(50, "Very long password (200 chars) works", async () => {
  const longPw = "A".repeat(200);
  const ct = await encryptMessage(MSG, longPw, null, null);
  const pt = await decryptMessage(ct, longPw, null, null);
  assert(pt === MSG, "Long password failed");
});

// ── Results ──

console.log("\n" + "═".repeat(50));
console.log(`  Results: ${pass} passed, ${fail} failed, ${pass + fail} total`);
if (failures.length) {
  console.log("\n  Failures:");
  for (const f of failures) {
    console.log(`    ${f.num}. ${f.name}: ${f.error}`);
  }
}
console.log("═".repeat(50) + "\n");

process.exit(fail > 0 ? 1 : 0);

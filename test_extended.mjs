/**
 * Dad's Morse v5 — Extended Crypto Test Suite
 *
 * Additional hardening, edge-case, and stress tests for the DMM1 v5
 * cryptographic container format. Run AFTER the main test_crypto.mjs passes.
 *
 *   Argon2id → HKDF-SHA256 → AES-256-GCM (header as AAD)
 *   Optional Ed25519 signatures (over header ‖ ciphertext, verified before decrypt)
 *
 * Requirements:
 *   Node.js 18+ (WebCrypto + Ed25519 support)
 *   npm install  (installs hash-wasm)
 *
 * Run:
 *   node test_extended.mjs
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
  const hashHex = await hashWasmArgon2id({
    password: new TextEncoder().encode(pass),
    salt,
    iterations: timeCost,
    memorySize: memCost,
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
// EXTENDED TESTS
// ============================================================

console.log("\n🔐 Dad's Morse v5 — Extended Crypto Test Suite\n");

// Pre-generate an Ed25519 keypair for signing tests
const testKeyPair = await subtle.generateKey(
  { name: "Ed25519" }, true, ["sign", "verify"]
);
const testPrivKeyB64 = bytesToBase64(new Uint8Array(
  await subtle.exportKey("pkcs8", testKeyPair.privateKey)
));
const testPubKeyB64 = bytesToBase64(new Uint8Array(
  await subtle.exportKey("spki", testKeyPair.publicKey)
));

const PW = "test-password-14ch!";
const PW2 = "wrong-password-here!";
const PEPPER = "signal-key-pepper";
const MSG = "Hello from Dad's Morse";

// ── Semantic security ──

console.log("── Semantic Security ──");

await test(1, "100 encryptions of same message produce 100 unique ciphertexts", async () => {
  const seen = new Set();
  for (let i = 0; i < 100; i++) {
    const ct = await encryptMessage("fixed message", PW, null, null);
    const hex = bytesToHex(ct);
    assert(!seen.has(hex), `Duplicate ciphertext on iteration ${i}`);
    seen.add(hex);
  }
});

await test(2, "Salt bytes are unique per encryption (CSPRNG)", async () => {
  const salts = [];
  for (let i = 0; i < 20; i++) {
    const ct = await encryptMessage("x", PW, null, null);
    salts.push(bytesToHex(ct.slice(6, 22)));
  }
  const unique = new Set(salts);
  assert(unique.size === 20, "All 20 salts should be unique");
});

await test(3, "IV bytes are unique per encryption (CSPRNG)", async () => {
  const ivs = [];
  for (let i = 0; i < 20; i++) {
    const ct = await encryptMessage("x", PW, null, null);
    ivs.push(bytesToHex(ct.slice(22, 34)));
  }
  const unique = new Set(ivs);
  assert(unique.size === 20, "All 20 IVs should be unique");
});

// ── Header integrity (AAD) ──

console.log("\n── Header Integrity (AAD) ──");

await test(4, "Tamper every header byte individually → all cause GCM failure", async () => {
  const ct = await encryptMessage(MSG, PW, null, null);
  for (let i = 0; i < DMM1_HEADER_LEN; i++) {
    const tampered = new Uint8Array(ct);
    tampered[i] ^= 0x01; // flip one bit
    let rejected = false;
    try { await decryptMessage(tampered, PW, null, null); }
    catch { rejected = true; }
    assert(rejected, `Tampered byte at offset ${i} should cause rejection`);
  }
});

await test(5, "Tamper ciphertext byte at multiple positions → all rejected", async () => {
  const ct = await encryptMessage(MSG, PW, null, null);
  const positions = [DMM1_HEADER_LEN, DMM1_HEADER_LEN + 5, ct.length - 1, ct.length - 8];
  for (const pos of positions) {
    const tampered = new Uint8Array(ct);
    tampered[pos] ^= 0xFF;
    let rejected = false;
    try { await decryptMessage(tampered, PW, null, null); }
    catch { rejected = true; }
    assert(rejected, `Tampered ciphertext at offset ${pos} should be rejected`);
  }
});

await test(6, "Truncated payload at various lengths → all rejected", async () => {
  const ct = await encryptMessage(MSG, PW, null, null);
  for (const len of [0, 1, 10, 33, 34, 40, ct.length - 1]) {
    let rejected = false;
    try { await decryptMessage(ct.slice(0, len), PW, null, null); }
    catch { rejected = true; }
    assert(rejected, `Truncation to ${len} bytes should be rejected`);
  }
});

await test(7, "Appended garbage → GCM auth failure", async () => {
  const ct = await encryptMessage(MSG, PW, null, null);
  const extended = new Uint8Array(ct.length + 10);
  extended.set(ct);
  extended.set(getRandomValues(new Uint8Array(10)), ct.length);
  await assertRejects(() => decryptMessage(extended, PW, null, null));
});

// ── Password edge cases ──

console.log("\n── Password Edge Cases ──");

await test(8, "Passwords differing by 1 char produce different ciphertext", async () => {
  const pw1 = "abcdefghijklmn";
  const pw2 = "abcdefghijklmo";
  const ct1 = await encryptMessage("x", pw1, null, null);
  const ct2 = await encryptMessage("x", pw2, null, null);
  assert(bytesToHex(ct1) !== bytesToHex(ct2));
});

await test(9, "Password with special characters round-trips", async () => {
  const pw = "p@$$w0rd!#%^&*()_+-=";
  const ct = await encryptMessage(MSG, pw, null, null);
  const pt = await decryptMessage(ct, pw, null, null);
  assert(pt === MSG);
});

await test(10, "Password with Unicode characters round-trips", async () => {
  const pw = "密码很长很安全的密码!!!";
  const ct = await encryptMessage(MSG, pw, null, null);
  const pt = await decryptMessage(ct, pw, null, null);
  assert(pt === MSG);
});

await test(11, "Password with newlines and tabs round-trips", async () => {
  const pw = "password\twith\nnewlines\r\nand\ttabs";
  const ct = await encryptMessage(MSG, pw, null, null);
  const pt = await decryptMessage(ct, pw, null, null);
  assert(pt === MSG);
});

await test(12, "Password with null bytes round-trips", async () => {
  const pw = "before\0after\0end!!";
  const ct = await encryptMessage(MSG, pw, null, null);
  const pt = await decryptMessage(ct, pw, null, null);
  assert(pt === MSG);
});

await test(13, "Very long password (1000 chars) round-trips", async () => {
  const pw = "X".repeat(1000);
  const ct = await encryptMessage(MSG, pw, null, null);
  const pt = await decryptMessage(ct, pw, null, null);
  assert(pt === MSG);
});

// ── Plaintext edge cases ──

console.log("\n── Plaintext Edge Cases ──");

await test(14, "Single character messages (various)", async () => {
  for (const c of ["a", " ", "\n", "\0", "🎉", "中"]) {
    const ct = await encryptMessage(c, PW, null, null);
    const pt = await decryptMessage(ct, PW, null, null);
    assert(pt === c, `Single char '${c}' round-trip failed`);
  }
});

await test(15, "Large message (10KB) round-trips", async () => {
  const msg = "ABCDEFGHIJ".repeat(1024); // 10240 bytes
  const ct = await encryptMessage(msg, PW, null, null);
  const pt = await decryptMessage(ct, PW, null, null);
  assert(pt === msg && pt.length === 10240);
});

await test(16, "Message with all printable ASCII round-trips", async () => {
  let msg = '';
  for (let i = 32; i < 127; i++) msg += String.fromCharCode(i);
  const ct = await encryptMessage(msg, PW, null, null);
  const pt = await decryptMessage(ct, PW, null, null);
  assert(pt === msg);
});

await test(17, "Binary-like message (null bytes, control chars) round-trips", async () => {
  let msg = '';
  for (let i = 0; i < 256; i++) msg += String.fromCharCode(i);
  const ct = await encryptMessage(msg, PW, null, null);
  const pt = await decryptMessage(ct, PW, null, null);
  // TextEncoder/TextDecoder handles replacement for non-UTF8, but the result should be consistent
  const expected = new TextDecoder().decode(new TextEncoder().encode(msg));
  assert(pt === expected);
});

await test(18, "Emoji-heavy message round-trips", async () => {
  const msg = "🏠🔑🔐💻📡🌍🎵🔊🐢✅❌🟢🔴🔵🟡🟣⚫⚪🔥💧";
  const ct = await encryptMessage(msg, PW, null, null);
  const pt = await decryptMessage(ct, PW, null, null);
  assert(pt === msg);
});

// ── Pepper / Signal Key edge cases ──

console.log("\n── Pepper Edge Cases ──");

await test(19, "Pepper with special characters round-trips", async () => {
  const pep = "señal-clave-🔑-pfeffer";
  const ct = await encryptMessage(MSG, PW, pep, null);
  const pt = await decryptMessage(ct, PW, pep, null);
  assert(pt === MSG);
});

await test(20, "Long pepper (500 chars) round-trips", async () => {
  const pep = "P".repeat(500);
  const ct = await encryptMessage(MSG, PW, pep, null);
  const pt = await decryptMessage(ct, PW, pep, null);
  assert(pt === MSG);
});

await test(21, "Pepper and password cannot be swapped", async () => {
  const pw = "password-here-long";
  const pep = "pepper-value-here!";
  const ct = await encryptMessage(MSG, pw, pep, null);
  // Try swapping pw and pepper
  await assertRejects(() => decryptMessage(ct, pep, pw, null));
});

await test(22, "Similar peppers produce different keys", async () => {
  const ct1 = await encryptMessage("x", PW, "pepper-a", null);
  const ct2 = await encryptMessage("x", PW, "pepper-b", null);
  // Can't decrypt ct1 with pepper-b
  await assertRejects(() => decryptMessage(ct1, PW, "pepper-b", null));
});

// ── Ed25519 Signing extended ──

console.log("\n── Ed25519 Signing Extended ──");

await test(23, "Signature is exactly 64 bytes", async () => {
  const ct = await encryptMessage(MSG, PW, null, testPrivKeyB64);
  const sig = ct.slice(DMM1_HEADER_LEN, DMM1_HEADER_LEN + 64);
  assert(sig.length === 64, `Signature should be 64 bytes, got ${sig.length}`);
});

await test(24, "Different messages produce different signatures (same key)", async () => {
  const ct1 = await encryptMessage("message one", PW, null, testPrivKeyB64);
  const ct2 = await encryptMessage("message two", PW, null, testPrivKeyB64);
  const sig1 = bytesToHex(ct1.slice(DMM1_HEADER_LEN, DMM1_HEADER_LEN + 64));
  const sig2 = bytesToHex(ct2.slice(DMM1_HEADER_LEN, DMM1_HEADER_LEN + 64));
  assert(sig1 !== sig2, "Different messages should have different signatures");
});

await test(25, "Different keys produce different signatures (same message)", async () => {
  const kp2 = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const priv2 = bytesToBase64(new Uint8Array(await subtle.exportKey("pkcs8", kp2.privateKey)));

  const ct1 = await encryptMessage(MSG, PW, null, testPrivKeyB64);
  const ct2 = await encryptMessage(MSG, PW, null, priv2);
  const sig1 = bytesToHex(ct1.slice(DMM1_HEADER_LEN, DMM1_HEADER_LEN + 64));
  const sig2 = bytesToHex(ct2.slice(DMM1_HEADER_LEN, DMM1_HEADER_LEN + 64));
  assert(sig1 !== sig2, "Different keys should produce different signatures");
});

await test(26, "Tampered signature bytes → verification fails", async () => {
  const ct = await encryptMessage(MSG, PW, null, testPrivKeyB64);
  // Tamper with a byte in the middle of the signature
  ct[DMM1_HEADER_LEN + 32] ^= 0xFF;
  await assertRejects(() => decryptMessage(ct, PW, null, testPubKeyB64), "Signature verification failed");
});

await test(27, "Unsigned message cannot be verified with a key (no error though)", async () => {
  // Unsigned message should decrypt fine even if a pubkey is provided
  // (because FLAG_SIGNED is not set, verification is skipped)
  const ct = await encryptMessage(MSG, PW, null, null);
  const pt = await decryptMessage(ct, PW, null, testPubKeyB64);
  assert(pt === MSG, "Unsigned message should decrypt even with pubkey provided");
});

await test(28, "Multiple keypairs: each verifies only its own signatures", async () => {
  const kp2 = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const priv2 = bytesToBase64(new Uint8Array(await subtle.exportKey("pkcs8", kp2.privateKey)));
  const pub2 = bytesToBase64(new Uint8Array(await subtle.exportKey("spki", kp2.publicKey)));

  // Sign with key 1, verify fails with key 2
  const ct = await encryptMessage(MSG, PW, null, testPrivKeyB64);
  await assertRejects(() => decryptMessage(ct, PW, null, pub2), "Signature verification failed");

  // Sign with key 2, verify fails with key 1
  const ct2 = await encryptMessage(MSG, PW, null, priv2);
  await assertRejects(() => decryptMessage(ct2, PW, null, testPubKeyB64), "Signature verification failed");
});

await test(29, "Signed + pepper + long message round-trip", async () => {
  const longMsg = "🐢 Turtle Dad Morse ".repeat(50);
  const ct = await encryptMessage(longMsg, PW, PEPPER, testPrivKeyB64);
  const pt = await decryptMessage(ct, PW, PEPPER, testPubKeyB64);
  assert(pt === longMsg);
});

// ── Cross-contamination / isolation ──

console.log("\n── Isolation / Cross-contamination ──");

await test(30, "Encrypting A then B: decrypting A still works", async () => {
  const ctA = await encryptMessage("Message A", PW, null, null);
  const ctB = await encryptMessage("Message B", PW, null, null);
  const ptA = await decryptMessage(ctA, PW, null, null);
  const ptB = await decryptMessage(ctB, PW, null, null);
  assert(ptA === "Message A" && ptB === "Message B");
});

await test(31, "Different passwords are fully isolated", async () => {
  const pw1 = "password-alpha-14!";
  const pw2 = "password-bravo-14!";
  const ct1 = await encryptMessage("secret-1", pw1, null, null);
  const ct2 = await encryptMessage("secret-2", pw2, null, null);

  // Each decrypts with own password
  assert(await decryptMessage(ct1, pw1, null, null) === "secret-1");
  assert(await decryptMessage(ct2, pw2, null, null) === "secret-2");

  // Cross-decrypt fails
  await assertRejects(() => decryptMessage(ct1, pw2, null, null));
  await assertRejects(() => decryptMessage(ct2, pw1, null, null));
});

// ── Morse codec extended ──

console.log("\n── Morse Codec Extended ──");

await test(32, "fromMorse handles extra whitespace gracefully", () => {
  const { hex, invalid } = fromMorse("  .-   -...  -.-.  ");
  assert(!invalid, "Should not be invalid");
  assert(hex === "abc", `Expected 'abc', got '${hex}'`);
});

await test(33, "fromMorse with invalid Morse produces invalid flag", () => {
  const { invalid } = fromMorse("..--.."); // not a valid hex Morse code
  assert(invalid, "Should be flagged as invalid");
});

await test(34, "Morse → Hex → Morse is idempotent", () => {
  const original = ".- -... -.-. -.. . ..-.";
  const { hex } = fromMorse(original);
  const rebuilt = toMorse(hex);
  assert(rebuilt === original, `Expected '${original}', got '${rebuilt}'`);
});

await test(35, "Hex → Morse for hex 'DEADBEEF'", () => {
  const morse = toMorse("DEADBEEF");
  const expected = "-.. . .- -.. -... . . ..-.";
  assert(morse === expected, `Expected '${expected}', got '${morse}'`);
});

await test(36, "Full pipeline: MSG → encrypt → base64 → bytes → decrypt", async () => {
  const ct = await encryptMessage(MSG, PW, null, null);
  const b64 = bytesToBase64(ct);
  const back = base64ToBytes(b64);
  const pt = await decryptMessage(back, PW, null, null);
  assert(pt === MSG);
});

// ── HKDF extended ──

console.log("\n── HKDF Extended ──");

await test(37, "HKDF output is always requested length", async () => {
  const master = getRandomValues(new Uint8Array(32));
  const salt = getRandomValues(new Uint8Array(16));
  for (const len of [16, 32, 48, 64]) {
    const key = await hkdf(master, salt, "test", len);
    assert(key.length === len, `Expected ${len} bytes, got ${key.length}`);
  }
});

await test(38, "HKDF: different salts → different output", async () => {
  const master = getRandomValues(new Uint8Array(32));
  const s1 = new Uint8Array(16); s1.fill(0x11);
  const s2 = new Uint8Array(16); s2.fill(0x22);
  const k1 = await hkdf(master, s1, "dmm1/aes-key", 32);
  const k2 = await hkdf(master, s2, "dmm1/aes-key", 32);
  assert(bytesToHex(k1) !== bytesToHex(k2));
});

await test(39, "HKDF: empty info string still works (produces valid key)", async () => {
  const master = getRandomValues(new Uint8Array(32));
  const salt = getRandomValues(new Uint8Array(16));
  const key = await hkdf(master, salt, "", 32);
  assert(key.length === 32);
});

// ── Argon2id extended ──

console.log("\n── Argon2id Extended ──");

await test(40, "Argon2id: empty password is rejected", async () => {
  const salt = getRandomValues(new Uint8Array(16));
  try {
    await argon2id("", salt);
    throw new Error("should have thrown");
  } catch (e) {
    assert(e.message !== "should have thrown", "empty password should be rejected");
  }
});

await test(41, "Argon2id: very long password (2000 chars)", async () => {
  const salt = getRandomValues(new Uint8Array(16));
  const key = await argon2id("Z".repeat(2000), salt);
  assert(key.length === 32);
});

await test(42, "Argon2id: unicode password", async () => {
  const salt = getRandomValues(new Uint8Array(16));
  const key = await argon2id("超级密码🔐", salt);
  assert(key.length === 32);
});

// ── Stress / randomized tests ──

console.log("\n── Stress / Randomized ──");

await test(43, "50 random encrypt-decrypt cycles (random messages + passwords)", async () => {
  for (let i = 0; i < 50; i++) {
    const msgLen = 1 + Math.floor(Math.random() * 200);
    const pwLen = 14 + Math.floor(Math.random() * 50);
    const msgBytes = getRandomValues(new Uint8Array(msgLen));
    // Use base64 to get printable characters for message
    const msg = bytesToBase64(msgBytes).slice(0, msgLen);
    const pw = bytesToBase64(getRandomValues(new Uint8Array(pwLen))).slice(0, pwLen);

    const ct = await encryptMessage(msg, pw, null, null);
    const pt = await decryptMessage(ct, pw, null, null);
    assert(pt === msg, `Random cycle ${i} failed`);
  }
});

await test(44, "20 random signed encrypt-decrypt cycles", async () => {
  for (let i = 0; i < 20; i++) {
    const msg = `Signed random message #${i} — ${bytesToBase64(getRandomValues(new Uint8Array(20)))}`;
    const pw = bytesToBase64(getRandomValues(new Uint8Array(20)));
    const usePepper = i % 3 === 0;
    const pep = usePepper ? bytesToBase64(getRandomValues(new Uint8Array(10))) : null;

    const ct = await encryptMessage(msg, pw, pep, testPrivKeyB64);
    const pt = await decryptMessage(ct, pw, pep, testPubKeyB64);
    assert(pt === msg, `Signed random cycle ${i} failed`);
  }
});

await test(45, "10 full Morse pipeline cycles (random data)", async () => {
  for (let i = 0; i < 10; i++) {
    const msg = `Morse test #${i}`;
    const pw = bytesToBase64(getRandomValues(new Uint8Array(16)));

    const ct = await encryptMessage(msg, pw, null, null);
    const hex = bytesToHex(ct);
    const morse = toMorse(hex);
    const { hex: hexBack, invalid } = fromMorse(morse);
    assert(!invalid, `Morse cycle ${i}: invalid decode`);
    const bytesBack = hexToBytes(hexBack);
    const pt = await decryptMessage(bytesBack, pw, null, null);
    assert(pt === msg, `Morse pipeline cycle ${i} failed`);
  }
});

// ── Container format validation ──

console.log("\n── Container Format Validation ──");

await test(46, "All-zero payload rejected (bad magic)", async () => {
  await assertRejects(() => decryptMessage(new Uint8Array(100), PW, null, null), "Invalid magic");
});

await test(47, "Valid magic but wrong version (0x01-0x04, 0x06-0xFF) all rejected", async () => {
  for (const ver of [0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0xFF]) {
    const ct = await encryptMessage("x", PW, null, null);
    ct[4] = ver;
    await assertRejects(() => decryptMessage(ct, PW, null, null), "Unsupported container version");
  }
});

await test(48, "Container with FLAG_SIGNED but only 34+16 bytes → truncated", async () => {
  // Build minimal container with signed flag set but no signature data
  const ct = await encryptMessage("x", PW, null, null);
  ct[5] = FLAG_SIGNED; // set signed flag
  await assertRejects(() => decryptMessage(ct, PW, null, testPubKeyB64));
});

await test(49, "Hex roundtrip for all byte values 0x00-0xFF", () => {
  const allBytes = new Uint8Array(256);
  for (let i = 0; i < 256; i++) allBytes[i] = i;
  const hex = bytesToHex(allBytes);
  assert(hex.length === 512, "Should be 512 hex chars");
  const back = hexToBytes(hex);
  assert(bytesToHex(back) === hex, "Byte round-trip failed");
});

await test(50, "Base64 roundtrip for all byte values 0x00-0xFF", () => {
  const allBytes = new Uint8Array(256);
  for (let i = 0; i < 256; i++) allBytes[i] = i;
  const b64 = bytesToBase64(allBytes);
  const back = base64ToBytes(b64);
  assert(bytesToHex(back) === bytesToHex(allBytes), "Base64 byte round-trip failed");
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

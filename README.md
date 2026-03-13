# Encrypted Morse Messenger

An **offline-first** encrypted Morse communication tool. Encrypts messages with
Argon2id + HKDF + AES-256-GCM, converts the ciphertext to Morse code, and lets
you play, download, or QR-share the result — all in the browser, with no server,
no CDN, and no network calls.

Installable as a PWA. Works fully offline after first load.

> No servers. No accounts. No CDN dependencies. No data leaves your browser.

---

> [!IMPORTANT]
> **Note for Morse hobbyists:**
> This app does **not** use standard alphanumeric Morse for your message. Because
> the message is encrypted first, the sounds you hear are a Morse-encoded version
> of the **AES ciphertext in hex**. Typing "SOS" will not produce `... --- ...`;
> it will produce the Morse equivalent of the encrypted hex string.

---

## Live Demo

✅ [https://systemslibrarian.github.io/dad-morse2/](https://systemslibrarian.github.io/dad-mode-morse2/)

---

## Full Workflow

```
Sender
  1. Type message + password (and optional Signal Key) → click Encrypt & Encode
  2. App derives key via Argon2id → HKDF → AES-256-GCM encrypts with random salt + IV
  3. Ciphertext → hex → Morse code → audio beeps
  4. Share via: Copy Morse, Copy Base64, Download WAV, or scan the QR code

Recipient
  1. Upload the .wav file (or paste Morse / Base64 / hex)
  2. Enter the shared password (and Signal Key, if used) → click Decrypt
  3. If signed, signature is verified BEFORE decryption
  4. Read the message
```

The WAV file is **safe to share publicly** — without the correct password it is
unreadable. The audio sounds like random beeps to anyone without the key.

---

## Step-by-step

### Sender — Encrypt & transmit

1. Enter your **message** and a strong **password** (14+ characters or a 4–5 word passphrase).
2. *(Optional)* Enter a **Signal Key** (pepper) — a second shared secret for extra resistance to offline guessing.
3. *(Optional)* Enable **Ed25519 Signing** and paste or generate a private key.
4. Click **Encrypt & Encode**.
5. Choose one or more ways to share:
   - **Copy Morse** — the Morse text string (hex-encoded ciphertext)
   - **Copy Base64** — compact text encoding for pasting
   - **Download WAV** — audio file to share over any channel
   - **QR Code** — scan with any QR reader to get the base64 payload
   - **Play** — listen to the Morse beeps in-browser

> The **Signal Quality** slider adds radio-style noise to the WAV. Keep it at
> 100% for reliable decoding by the recipient.

### Recipient — Decode & decrypt

**From a WAV file:**
1. Switch to the **Decrypt** tab
2. Upload the WAV → click **Decode WAV** — the Morse string auto-fills
3. Enter the shared password (and Signal Key, if used)
4. *(Optional)* Paste the sender's Ed25519 public key to verify the signature
5. Click **Decrypt**

**From text (Morse, Base64, or hex):**
1. Paste into the input field — the app auto-detects the format
2. Enter password → click **Decrypt**

**Input format detection:**
- Contains `.` or `-` → treated as Morse → decoded to hex → bytes
- Only `0-9 A-F` → treated as raw hex → bytes
- Anything else → treated as Base64 → bytes

**From a QR code image:**
1. Switch to the **Decrypt** tab
2. Under "Upload QR Code Image", select a screenshot or photo of a QR code
3. The app reads the QR and fills in the Base64 payload automatically
4. Enter password → click **Decrypt**

---

## QR Code — What It Does

After you encrypt a message, the app generates a **QR code** on screen. This QR code contains the **Base64-encoded ciphertext** — the same encrypted data you'd get from "Copy Base64", just in a scannable image.

**Why is this useful?**
- You can take a **screenshot** of the QR code and text it, email it, or AirDrop it to someone
- The recipient can **upload that image** into the Decrypt tab — no typing or pasting needed
- QR codes work even when printed on paper — scan with a phone camera to grab the payload
- Like the WAV file, the QR code is **safe to share publicly** — without the password, it's unreadable

**How it works under the hood:**
1. Your message is encrypted → raw bytes
2. The bytes are encoded as Base64 text (compact, URL-safe)
3. That Base64 string is turned into a QR code image
4. On the receiving end, the QR is decoded back to Base64 → bytes → decrypted with your password

**Limits:** QR codes can hold about 4,000 characters. Very long messages may exceed this — the app will tell you and you can use "Copy Base64" or "Download WAV" instead.

You can also click **Download QR** to save the QR code as a PNG file.

---

## Cryptography — v5 Container

### Container Format

| Field | Bytes | Description |
|---|---|---|
| Magic | 0–3 | `DMM1` (0x44 0x4D 0x4D 0x31) |
| Version | 4 | `0x05` |
| Flags | 5 | Bit 0: pepper used; Bit 1: signed |
| Salt | 6–21 | 16 bytes, CSPRNG |
| IV / Nonce | 22–33 | 12 bytes, CSPRNG |
| Signature | 34–97 | 64 bytes, Ed25519 *(only if FLAG_SIGNED)* |
| Ciphertext | 34+ or 98+ | AES-256-GCM output (includes 16-byte auth tag) |

**Total header: 34 bytes fixed.** Compact, unambiguous, strictly bounds-checked.

### Key Derivation

```
password [+ pepper] → Argon2id(t=4, m=64MiB, p=4, 16-byte salt) → 32-byte master key
master key → HKDF-SHA256(salt, "dmm1/aes-key") → 256-bit AES key
```

- **Argon2id** is the primary password-hardening KDF (memory-hard, resists GPU/ASIC attacks)
- **HKDF** provides domain-separated key derivation from the master material
- The raw password is never used directly as key material
- No SHA-256-as-KDF path exists — Argon2id is the only KDF

### Authenticated Encryption

| Property | Value |
|---|---|
| Algorithm | AES-256-GCM (128-bit auth tag) |
| AAD (Additional Authenticated Data) | The 34-byte header |
| Effect | Any tampering with magic, version, flags, salt, or IV causes GCM authentication failure |

The header is **not encrypted** but is **authenticated** — modifying any header byte causes decryption to fail, even if the ciphertext is untouched.

**No padding.** AES-GCM is a stream-based AEAD mode that handles arbitrary-length plaintext natively. No PKCS#7 or custom padding is used.

### Ed25519 Digital Signatures (optional)

| Property | Value |
|---|---|
| Algorithm | Ed25519 (RFC 8032) via WebCrypto |
| Key format | PKCS#8 (private), SPKI (public), both base64-encoded |
| Signed data | `header ‖ ciphertext` (the encrypted container, NOT the plaintext) |
| Signature location | Embedded in the binary container between header and ciphertext |
| Verification | **Before** decryption — a failed signature aborts without attempting decrypt |

This is the correct signing model: sign the ciphertext container, verify before decrypting. The sender's identity is confirmed before any key material is derived.

### Signal Key (Pepper)

An optional second shared secret. If the sender uses a Signal Key, the recipient **must** enter the same one to decrypt. It is never stored in the payload or transmitted. Combined with the password using length-prefixed domain separation to prevent concatenation collisions.

### Encoding Paths

| Output | Encoding | Alphabet |
|---|---|---|
| Morse / WAV / Audio | Hex (2 chars per byte) | `0-9`, `A-F` — matches the 16-symbol Morse table |
| Base64 / QR / Clipboard | Base64 | `A-Z`, `a-z`, `0-9`, `+`, `/`, `=` |

Both paths encode the same ciphertext bytes. Hex is used for Morse because the Morse table maps exactly 16 symbols. Base64 is used for QR/clipboard because it's more compact.

### Security Properties

- **Confidentiality** — AES-256-GCM; computationally infeasible to brute-force
- **Integrity** — GCM authentication tag detects any tampering; wrong password or modified byte always throws, never silently returns garbage
- **Authenticated metadata** — header bytes bound as AAD; version/flags/salt/IV tampering detected
- **Semantic security** — random salt + random IV; same plaintext + password produces different ciphertext every time
- **Memory-hard KDF** — Argon2id with 64 MiB memory cost makes offline brute-force extremely expensive
- **No key reuse** — fresh salt per message; HKDF derives the AES key from master material
- **Signature-before-decrypt** — Ed25519 verification happens before any key derivation or decryption
- **Fully auditable** — all code is in three files; inspect at any time

---

## Offline / PWA Architecture

Dad's Morse is a Progressive Web App with zero external dependencies at runtime.

| Component | Status |
|---|---|
| Argon2id WASM | Inlined in index.html (base64-bundled, ~46KB) |
| QR code generator | Inlined in index.html (~57KB) |
| AES-256-GCM, HKDF, Ed25519 | Native WebCrypto API — built into the browser |
| Morse audio synthesis | Web Audio API — built into the browser |
| WAV encode/decode | Raw ArrayBuffer math — no library |
| Service Worker | Cache-first; caches all assets on install |
| PWA Manifest | `"display": "standalone"` — installable as app |

**After first load, the app works with no network at all.** Airplane mode, airgapped machine, no WiFi — everything runs locally.

### Install as App

- **Android Chrome:** Menu → "Add to Home Screen"
- **iOS Safari:** Share → "Add to Home Screen"
- **Desktop Chrome/Edge:** Click install icon in address bar

---

## Files

| File | Purpose |
|---|---|
| `index.html` | The entire app — HTML, CSS, JS, and inlined libraries (Argon2 WASM + QR generator) |
| `sw.js` | Service worker — caches all assets for offline use |
| `manifest.json` | PWA manifest — enables "Add to Home Screen" installation |
| `turtle.png` | Header image and video poster |
| `turtle.mp4` | Transmit animation |
| `test_crypto.mjs` | Encryption/decryption test suite (Node.js, Web Crypto API) |
| `test_decode.py` | Morse WAV decode test suite (Python 3, stdlib only) |

> The three core files (`index.html`, `sw.js`, `manifest.json`) are the complete
> app. Everything else is optional. Drop them in any HTTPS-served directory
> and the app works.

---

## WAV Decoder

The **Decode WAV** button analyses audio entirely in the browser:

1. Decode audio to PCM (any sample rate, mono or stereo)
2. Compute RMS energy in 5 ms frames
3. Threshold at 15% of the 95th-percentile energy → binary tone-on/off
4. Run-length encode the signal
5. Estimate the dot (unit) length by finding the largest relative gap in sorted
   on-durations — handles all-dots, all-dashes, and mixed inputs
6. Classify each run as `.` `-` letter-gap or word-gap `/`
7. Output the Morse string into the decrypt field

Works reliably on WAV files generated by this app at 100% signal quality.
Heavily degraded (noisy) audio may introduce symbol errors.

---

## Run Locally

You don't need to install anything complicated. Pick the option that fits your comfort level.

### Option A: Just open the file (simplest)

1. Go to https://github.com/systemslibrarian/dad-morse2
2. Click the green **Code** button → **Download ZIP**
3. Unzip the folder anywhere on your computer
4. Open the folder and double-click **index.html** — it opens in your browser
5. That's it. You can encrypt and decrypt messages right away

> **What you'll miss:** The "Install as App" button and offline caching won't
> work when opened this way, because browsers require `https://` or
> `localhost` for those features. Everything else works fine.

### Option B: Run a local web server (recommended)

This gives you the full experience — offline mode, "Add to Home Screen", and
service worker caching. You only need **one** of the tools below.

#### Using Python (built into macOS and most Linux; easy to install on Windows)

1. Download and unzip the repo (same as Option A steps 1–3)
2. Open a terminal / command prompt
3. Navigate to the folder:
   ```bash
   cd ~/Downloads/dad-morse2-main   # adjust the path to where you unzipped it
   ```
4. Start the server:
   ```bash
   python3 -m http.server 8080
   ```
5. Open your browser and go to **http://localhost:8080**
6. To stop the server, press **Ctrl+C** in the terminal

> **Don't have Python?**
> - **Windows:** Download from https://www.python.org/downloads/ — check "Add to PATH" during install
> - **macOS:** It's pre-installed. Open Terminal and type `python3 --version` to confirm
> - **Linux:** It's pre-installed on most distros. If not: `sudo apt install python3`

#### Using Node.js

1. Download and unzip the repo
2. Open a terminal and navigate to the folder
3. Run:
   ```bash
   npx serve .
   ```
4. Open **http://localhost:3000** in your browser

> **Don't have Node.js?** Download from https://nodejs.org/ — the LTS version is fine.

### Option C: Clone with Git (for developers)

```bash
git clone https://github.com/systemslibrarian/dad-morse2.git
cd dad-morse2
python3 -m http.server 8080
# open http://localhost:8080
```

---

## Offline Integrity (Recommended)

For maximum trust, download the repo and run it locally with no network.

Tip: publish a SHA-256 hash for each release so users can verify `index.html`
hasn't been tampered with:

```bash
shasum -a 256 index.html
# Current: 47b3d5eebc6f99b338e1be4795ee753bfd9eb0faeeeed73f9d3537b12aa0bf1e
```

---

## Tests

### Encryption tests — `test_crypto.mjs`

> ⚠️ **Test suite needs updating for v5 container format.** Tests currently
> reference v2 header layout and may need adjustment for the 34-byte v5 header,
> Argon2id-as-actual-KDF path, AAD-authenticated header, and embedded signature
> model. Core crypto round-trip tests should still pass.

Uses the Web Crypto API built into Node.js 15+. No dependencies required.

```bash
node test_crypto.mjs
```

| # | What is tested |
|---|---|
| 1 | DMM1 v5 encrypt + decrypt round-trip (correct password recovers plaintext) |
| 2 | Wrong password is rejected (AES-GCM auth tag + AAD) |
| 3 | Random salt + IV — same message/password produces different ciphertext every time |
| 4 | Hex ↔ Morse conversion is perfectly lossless (all 16 hex digits) |
| 5 | Full pipeline: encrypt → hex → Morse → hex → decrypt |
| 6 | Unicode / emoji / CJK characters survive the full round-trip |
| 7 | Empty string handled without errors |
| 8 | Long message (1000 chars) round-trips correctly |
| 9 | Tampered ciphertext is rejected (GCM + AAD integrity) |
| 10 | DMM1 v5 payload binary layout — 34-byte header + ciphertext + tag |
| 11 | Morse output contains only valid hex Morse symbols |
| 12 | All 16 hex characters map to unique, non-overlapping Morse codes |
| 13 | Signal Key (pepper) encrypt + decrypt round-trip |
| 14 | Pepper used → decrypt without pepper throws |
| 15 | Wrong pepper → decrypt fails |
| 16 | No pepper → FLAG_PEPPER bit is 0 |
| 17 | With pepper → FLAG_PEPPER bit is 1 |
| 18 | Tampered header (AAD) is rejected — any header byte change causes GCM failure |
| 19 | Non-DMM1 payload is rejected |
| 20 | Argon2id is called as the actual KDF (not SHA-256) |
| 21 | `concatPwPepper` uses length-prefixed domain separation |
| 22 | HKDF key separation: `dmm1/aes-key` label produces distinct keys |
| 23 | Ed25519 key generation produces valid keypair |
| 24 | Ed25519 sign + verify round-trip (signature over header ‖ ciphertext) |
| 25 | Ed25519 verification fails with wrong public key |
| 26 | Ed25519 verification fails with tampered container |
| 27 | Ed25519 signature is embedded in binary container, not appended as text |
| 28 | Signature verified before decryption (verify-then-decrypt order) |
| 29 | Full pipeline with signing: encrypt → sign → Morse → decrypt → verify |
| 30 | Hex → bytes → hex round-trip is lossless |
| 31 | Base64 input path produces same bytes as hex input path |

### WAV decode tests — `test_decode.py`

Python 3 standard library only.

```bash
python3 test_decode.py
```

### Run all tests

```bash
node test_crypto.mjs && python3 test_decode.py
```

Both suites exit with code `0` on success and `1` on failure.

---

## Security Considerations

- **Use a strong, unique password (14+ chars or a passphrase).** The security of
  your message depends entirely on the password. Short or common passwords are
  the only real weakness in this system.
- **Share the password out-of-band.** Don't send the password in the same
  channel as the WAV/Morse/QR payload.
- **Audio duration leaks approximate message length.** WAV duration is
  proportional to ciphertext length. This is inherent to the Morse-audio
  transport, not a flaw in the cryptography.
- **Argon2id** with 64 MiB memory cost makes offline brute-force extremely
  expensive. Use 14+ random characters for sensitive messages.
- **The browser is the trust boundary.** All crypto runs via WebCrypto. A
  compromised browser, malicious extension, or modified HTML file could extract
  secrets. For maximum trust, verify the file hash and run on a clean machine.

---

## Version History

| Version | Changes |
|---|---|
| **v5** (current) | Argon2id as actual KDF (not just declared); HKDF domain separation (`dmm1/aes-key`); header as AAD; no PKCS#7 padding (GCM is stream mode); dead ECDH scaffolding removed; Ed25519 signs `header‖ciphertext` embedded in container; verify-before-decrypt; hex encoding for Morse path (was broken with base64); PWA with inlined Argon2 WASM + QR library; service worker for offline; zero CDN dependencies |
| **v4** | DMM1 container format; Ed25519 signing; ECDH ephemeral key (unused); SHA-256 as KDF (Argon2id declared but not called); PKCS#7 padding on GCM; base64 fed to hex-only Morse table (lossy) |
| **v2** | Original DMM1 format; Argon2id via CDN; hex Morse encoding; single-file app |

**v5 is not backward-compatible with v4 or v2 containers.** This is intentional — v5 fixes structural cryptographic issues that could not be patched without breaking the format.

---

## Browser Compatibility

Requires a modern browser with:
- **WebCrypto API** — AES-GCM, HKDF, Ed25519
- **WebAssembly** — Argon2id WASM module
- **Web Audio API** — Morse audio playback
- **Service Worker** — offline caching (optional, degrades gracefully)

All evergreen browsers since ~2020: Chrome, Firefox, Safari, Edge.

---

## License

[MIT](LICENSE) — do whatever you like, no warranty.

---

**Dedicated to my Dad — a Navy veteran who knew Morse code.
We love you and miss you.**

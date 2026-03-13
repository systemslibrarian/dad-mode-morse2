# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| v5 (current) | ✅ Active |
| v4 | ❌ Deprecated — structural crypto issues |
| v2 | ❌ Deprecated |

Only the current v5 container format is supported. v4 and v2 containers cannot
be decrypted by the current code. This is intentional.

## Reporting a Vulnerability

If you find a security issue in the cryptographic implementation, container
format, or key derivation path, please report it responsibly:

1. **Do not open a public GitHub issue** for security vulnerabilities.
2. Email: *(add your security contact email here)*
3. Include: description of the issue, steps to reproduce, and your assessment
   of severity.
4. Expected response: acknowledgment within 48 hours, fix or mitigation within
   7 days for critical issues.

## Cryptographic Architecture

| Component | Implementation |
|-----------|---------------|
| Password hardening | Argon2id (t=4, m=64MiB, p=4) via WASM |
| Key derivation | HKDF-SHA256 with domain label `dmm1/aes-key` |
| Encryption | AES-256-GCM with 128-bit auth tag |
| Metadata authentication | Header bytes as AAD (Additional Authenticated Data) |
| Signing | Ed25519 over `header ‖ ciphertext`, verified before decryption |
| Random values | `crypto.getRandomValues()` (browser CSPRNG) |

## Trust Model

### What this app protects against

- Passive interception of the WAV/Morse/QR/base64 payload
- Server-side data access (there is no server)
- Offline brute-force (Argon2id with 64 MiB memory cost)
- Ciphertext tampering (GCM auth tag + AAD)
- Header tampering (AAD-authenticated metadata)
- Sender impersonation (Ed25519 signature, when used)

### What this app does NOT protect against

- Weak passwords — the entire security model depends on password entropy
- Compromised browser or device — a malicious browser extension, modified HTML
  file, or compromised OS can extract secrets
- Endpoint compromise — if the sender's or recipient's device is compromised,
  encryption is irrelevant
- Message length leakage — WAV duration and ciphertext length reveal
  approximate plaintext length
- Key exchange — the password must be shared out-of-band; this app provides no
  key agreement protocol

### Honest claims

- This is **not** end-to-end encrypted in the Signal sense — there is no key
  agreement protocol and no forward secrecy
- This **is** a strong password-based encryption container with authenticated
  metadata, suitable for air-gapped message transfer where both parties share
  a pre-established password
- The browser is the trust boundary — all crypto runs in WebCrypto, which is
  audited and well-maintained in evergreen browsers

## Verifying Integrity

For maximum trust, download the repo and verify the SHA-256 hash of
`index.html` against the published value before use:

```bash
shasum -a 256 index.html
```

Run locally with no network connection for air-gapped operation.

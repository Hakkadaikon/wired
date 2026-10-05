# Security documents

Index of `docs/security/`. The user-facing overview of wired's security
properties is [`docs/security.md`](../security.md); this directory holds the
audit records behind it.

| Document | What it is | Current state (2026-10-05) |
|---|---|---|
| [vuln-ledger.md](vuln-ledger.md) | One row per vulnerability class or advisory the SDK's protocols are exposed to (spec paragraphs, peer-implementation advisories, literature, npm audits), each with a verdict and the test that defends it | 838 rows: 59 fixed, 416 already safe, 363 not applicable, 0 not done. Check: `python3 scripts/vulnaudit/ledger_check.py docs/security/vuln-ledger.md` |
| [feature-gaps.md](feature-gaps.md) | The ledger rows closed as not applicable only because the feature is absent (ECH, P-521, client certificates, CBC suites, revocation, TLS 1.2, ...); adding the feature re-opens them | 57 rows in 26 groups |
| [boringssl-vectors.md](boringssl-vectors.md) | BoringSSL FileTest vectors (pinned `dd73e69a`) as a third-party crypto oracle: AES-GCM, ChaCha20-Poly1305, X25519, Ed25519, ECDSA P-256/P-384, HMAC-SHA256/384 | 0 failures; skips are unimplemented curves / hashes and non-96-bit nonces. Vectors: `tests/vectors/boringssl/` |
| [wycheproof-vectors.md](wycheproof-vectors.md) | Wycheproof attack vectors (C2SP/wycheproof `testvectors_v1`, pinned `3fa63dd0`) as a third-party oracle: AES-GCM, ChaCha20-Poly1305, X25519, Ed25519, ECDSA P-256/P-384, RSA PKCS#1 v1.5 / PSS, HMAC-SHA256, HKDF-SHA256 | 5754 cases, 0 failures, 155 skips; documents which `invalid` rejections are by construction (54) rather than through wired's code. Vectors: `tests/vectors/wycheproof/` |

Related, outside this directory:

- [`docs/features/known-limitations.md`](../features/known-limitations.md) —
  every known limitation and deliberate spec deviation, by category.
- `docs/superpowers/specs/2026-09-12-vuln-and-perf-audit-plan.md` — the
  method behind the vulnerability ledger.

## Where each crypto primitive is checked

| Primitive | RFC / FIPS tests | BoringSSL | Wycheproof |
|---|---|---|---|
| AES-128/256-GCM | yes | yes | yes |
| ChaCha20-Poly1305 | yes | yes | yes |
| X25519 | yes | yes | yes |
| Ed25519 | yes | yes | yes |
| ECDSA P-256 / P-384 | yes | yes | yes (P-384 with SHA-384 and SHA-512) |
| RSA PKCS#1 v1.5 / PSS verify | yes | no vectors in allowed files | yes (e = 65537) |
| HMAC-SHA256 / SHA384 | yes | yes | SHA256 only |
| HKDF-SHA256 | yes | no vectors at the pinned commit | yes |
| SHA-256 / 384 / 512 | yes (SHA-512: one FIPS 180-4 known answer) | via HMAC (no SHA-512) | as the digest of ECDSA / RSA / HMAC / HKDF cases |

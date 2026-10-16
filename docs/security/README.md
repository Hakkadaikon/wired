# Security documents

This page is the map of `docs/security/`: it says what each audit record is
for and when you would open it. Read it when you need evidence behind a
security claim, for example to answer "has wired been checked against
attack X?" or "which test proves this crypto primitive is correct?". For the
user-facing summary of wired's security properties, start with
[`docs/security.md`](../security.md) instead.

## Two ideas behind these records

A **vulnerability ledger** is a list of every known way a protocol like
wired's can be attacked, with a decision for each one. The entries come from
the specs themselves (RFC paragraphs that warn about an attack), from bugs
found in other QUIC / TLS implementations (CVEs and advisories), from
research papers, and from `npm audit` of the browser samples. Each entry gets
one of three verdicts:

- **fixed**: wired had the problem, it was fixed, and a test pins the fix.
- **already safe**: wired never had the problem. Usually a test proves it; for
  a few structural rows the Rationale explains why the code cannot be attacked.
- **not applicable**: the attacked feature or code path does not exist in
  wired; the entry records why.

A **third-party test-vector oracle** checks wired's crypto against expected
values written by someone else. Our own tests are written by the same people
who wrote the code, so a misreading of the spec can end up in both and the
test still passes. BoringSSL (Google's TLS library) and Project Wycheproof
(a collection of known attack inputs) publish files of inputs and expected
outputs. wired runs them unchanged, so a disagreement means wired is wrong,
not that the test was written to match wired.

## The documents

| Document | Open it when | Current state |
|---|---|---|
| [vuln-ledger.md](vuln-ledger.md) | you want the verdict and test for one attack class or advisory | 840 rows, all closed: 61 fixed, 415 already safe, 364 not applicable |
| [feature-gaps.md](feature-gaps.md) | you plan to add a feature wired lacks today | 57 ledger rows in 26 feature groups |
| [boringssl-vectors.md](boringssl-vectors.md) | you want BoringSSL's verdict on a primitive | 1634 cases, 1523 pass, 0 fail, 111 skip |
| [wycheproof-vectors.md](wycheproof-vectors.md) | you want to know which attack inputs are rejected | 6296 cases: 6141 correct (54 of them by construction), 0 fail, 155 skip |

Notes on each row:

- **vuln-ledger.md**: one row per attack class, with the source (CVE, RFC
  section, paper), the verdict, the test that pins it, and the commit. The
  file's format is checked by
  `python3 scripts/vulnaudit/ledger_check.py docs/security/vuln-ledger.md`,
  which also prints the row totals. The verdict counts above are counted
  from the rows' Verdict column.
- **feature-gaps.md**: the ledger rows that are safe only because a
  feature is missing (most are not applicable, five are already safe for
  the part that exists), such as Encrypted
  Client Hello, client certificates, CBC cipher suites, revocation checking
  or TLS 1.2. Adding that feature re-opens those rows, so read this before
  you add one.
- **boringssl-vectors.md**: results of BoringSSL's FileTest vectors (pinned
  commit `dd73e69a`) for AES-GCM, ChaCha20-Poly1305, X25519, Ed25519, ECDSA
  P-256 / P-384 / P-521 and HMAC-SHA256 / 384 / 512. Skips are curves and
  hashes wired does not implement, AES-GCM nonces that are not 96 bits,
  plus one X25519 stress test that BoringSSL itself disables.
  The vectors live in `tests/vectors/boringssl/`.
- **wycheproof-vectors.md**: results of the Wycheproof vectors (C2SP
  `testvectors_v1`, pinned `3fa63dd0`) for the same AEADs, curves and
  signatures plus RSA PKCS#1 v1.5 / PSS, HMAC-SHA256 and HKDF-SHA256. It
  also lists the 54 "invalid" cases that count as rejected without any
  wired code running, because wired's API cannot express the input (an
  AES-192 key, a nonce that is not 96 bits, or an Ed25519 signature that is
  not 64 bytes). The vectors live in
  `tests/vectors/wycheproof/`.

Related, outside this directory:

- [`docs/features/known-limitations.md`](../features/known-limitations.md):
  every known limitation and deliberate spec deviation, by category.
- [`docs/superpowers/specs/2026-09-12-vuln-and-perf-audit-plan.md`](../superpowers/specs/2026-09-12-vuln-and-perf-audit-plan.md):
  the method used to build the vulnerability ledger.

## Where each crypto primitive is checked

Each primitive has three possible kinds of check: wired's own tests built from
the example inputs and outputs printed in the RFC or FIPS standard ("known
answers"), the BoringSSL vectors, and the Wycheproof vectors. A "no" means that
kind of check does not exist for the primitive; the notes below the table say
why.

| Primitive | RFC / FIPS tests | BoringSSL | Wycheproof |
|---|---|---|---|
| AES-128-GCM | yes | yes | yes |
| AES-256-GCM | no (1) | yes | yes |
| ChaCha20-Poly1305 | yes | yes | yes |
| X25519 | yes | yes | yes |
| Ed25519 | yes | yes | yes |
| ECDSA P-256 | yes | yes | yes |
| ECDSA P-384 | no (1) | yes | yes (SHA-384 and SHA-512) |
| ECDSA P-521 | no (1) | yes | yes (SHA-512) |
| RSA PKCS#1 v1.5 / PSS verify | no (1) | no (2) | yes (e = 65537) (5) |
| HMAC-SHA256 / 384 / 512 | yes | yes | SHA256 only |
| HKDF-SHA256 | yes | no (3) | yes |
| SHA-256 / 384 / 512 | yes (4) | via HMAC (6) | via ECDSA / RSA / HMAC / HKDF (6) |

- (1) AES-256-GCM, P-384, P-521 and RSA have their own tests, but their
  expected values were generated with OpenSSL or Python, not taken from an
  RFC or FIPS known answer. The
  third-party vectors fill that gap. P-521 is used to verify certificate
  chains only.
- (2) BoringSSL's allowed vector files have no RSA vectors.
- (3) BoringSSL moved its HKDF vectors into C++ test source, so the pinned
  commit has no vector file for it.
- (4) SHA-512 has a single FIPS 180-4 known answer (the digest of the empty
  string).
- (5) e = 65537 is the usual RSA public exponent; wired verifies only this
  one.
- (6) "via" means the hash has no vectors of its own there, but every case
  of the named primitives hashes its input first, so a wrong digest would
  fail them.

For what X25519 and SHA-256 do inside the TLS handshake, see the guide pages
[X25519](https://hakkadaikon.github.io/wired/guide/en/tls/x25519/) and
[SHA-256](https://hakkadaikon.github.io/wired/guide/en/tls/sha256/).

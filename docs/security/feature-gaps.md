# Not applicable because the feature is absent

These ledger rows (docs/security/vuln-ledger.md) describe a vulnerability class
in a feature this SDK does not implement. They are closed as not applicable,
not as defended: adding the feature later re-opens every row in its group.
The list is the authoritative statement of those gaps for security review.

| Feature absent | Ledger rows | Consequence for a deployment |
|---|---|---|
| Encrypted Client Hello (ECH, draft-ietf-tls-esni) | V-0238, V-0240 | the class cannot occur; adding the feature requires re-triaging these rows |
| ECDSA P-521 signature scheme (only P-256 / P-384, RSA-PSS, Ed25519) | V-0247 | certificates signed with P-521 cannot be verified |
| Client certificate authentication (CertificateRequest / mutual TLS) | V-0268, V-0330, V-0377, V-0383, V-0378, V-0386 | peer authentication is server-only; client identity must come from the application layer |
| Finite-field DHE groups (only X25519 / P-256 ECDHE) | V-0270 | the class cannot occur; adding the feature requires re-triaging these rows |
| RSA-PSK / RSA key transport (RSA is verify-only) | V-0271, V-0274, V-0660, V-0696, V-0711, V-0739, V-0741 | the class cannot occur; adding the feature requires re-triaging these rows |
| CBC-mode cipher suites (only AES-GCM and ChaCha20-Poly1305) | V-0285, V-0759 | the class cannot occur; adding the feature requires re-triaging these rows |
| certificate_compression extension (RFC 8879) | V-0299 | the class cannot occur; adding the feature requires re-triaging these rows |
| External PSK (only server-sealed resumption tickets) | V-0300 | only ticket resumption; Selfie-style reflection has no surface |
| Revocation checking: CRL, OCSP, OCSP stapling, AIA / CRL-DP fetching | V-0324, V-0528, V-0531, V-0557, V-0560, V-0573, V-0620, V-0621 | revocation is an operator concern (short-lived certificates, out-of-band rotation) |
| TLS 1.2 and earlier: extended_master_secret, middlebox compatibility mode, SSLv2 CLIENT-HELLO | V-0347, V-0360, V-0366 | this is a TLS 1.3-only / QUIC-only stack |
| Client-side retry-with-different-parameters loop | V-0351 | the class cannot occur; adding the feature requires re-triaging these rows |
| ECN self-marked CE probe (socket-wide IP_TOS only, no per-send cmsg) | V-0223 | suppressed CE reports are still caught by the RFC 9000 13.4.2.1 count floor |
| DSA | V-0576, V-0655, V-0677, V-0687 | the class cannot occur; adding the feature requires re-triaging these rows |
| Curve448 / Ed448 / Ed25519ctx-ph context parameter | V-0718, V-0729, V-0730, V-0732, V-0734, V-0766 | the class cannot occur; adding the feature requires re-triaging these rows |
| Init/Update/Finish (streaming) signature API (single-buffer only) | V-0736, V-0737 | the class cannot occur; adding the feature requires re-triaging these rows |
| Private key generation (keys are supplied as raw seeds / scalars) | V-0747 | the class cannot occur; adding the feature requires re-triaging these rows |
| PKCS#7 / CMS parsing | V-0526 | the class cannot occur; adding the feature requires re-triaging these rows |
| RFC 4518 DN string normalisation in name constraints (exact-bytes match for the non-directoryName forms) | V-0547 | the class cannot occur; adding the feature requires re-triaging these rows |
| Signed Certificate Timestamps / Certificate Transparency | V-0549 | the class cannot occur; adding the feature requires re-triaging these rows |
| rfc822Name (email) GeneralName in SAN / name constraints | V-0556 | the class cannot occur; adding the feature requires re-triaging these rows |
| Composite / multi-algorithm signatures (draft PKIX CompositeSignature) | V-0568 | the class cannot occur; adding the feature requires re-triaging these rows |
| HTTP/1.1 backend connections (no proxy role) | V-0435 | the class cannot occur; adding the feature requires re-triaging these rows |
| HTTP/3 server push (PUSH_PROMISE) | V-0446 | the class cannot occur; adding the feature requires re-triaging these rows |
| QPACK intermediary role (one dynamic table per connection, no forwarding) | V-0468 | the class cannot occur; adding the feature requires re-triaging these rows |
| Client-side WebTransport session opening | V-0510 | the class cannot occur; adding the feature requires re-triaging these rows |
| MoQT authorization token schemes (CAT / Privacy Pass); the token is decoded and handed to the authorize hook | V-0794 | the relay decides authorization through wired_moqt_hub.authorize_subscribe |

57 rows in 26 groups. Everything else in the ledger is either a
defended behaviour with a named test or an informational / design-level row.

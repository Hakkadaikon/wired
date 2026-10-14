# Not applicable because the feature is absent

This page lists security risks that do not apply to wired, but only because
it leaves a feature out. Read it before a security review, and before you add
any of the features below: adding one brings its risks back.

## What a ledger row is

The [vulnerability ledger](vuln-ledger.md) has one row per known kind of
attack (a "vulnerability class"), each with an ID like `V-0238`. A row comes
from, for example, a published bug in another TLS or QUIC library, a security
paragraph in an RFC, or a research paper. Each row ends with a verdict:

- **fixed** or **already-safe**: wired has the code the attack targets, and
  the row is *defended*. Usually a named test shows the attack fails. For a
  few structural rows there is no test, and the Rationale explains why the
  code cannot be attacked.
- **not applicable** (`n/a`): wired has no code the attack could target, so
  there is nothing to test. The row's Rationale says why. Some `n/a` rows are
  informational: they record a design note in an RFC or an operator concern,
  not an attack on wired's code.

The difference matters. A defended row stays safe when the code around it
changes, because its test (where it has one) keeps running. An `n/a` row has
no test. When it is `n/a` because a feature is missing, it is safe only while
the feature stays out.

## Why this list matters when you add a feature

The rows below are safe today for one reason only: a feature is missing. If
you add the feature, every row in its group becomes a real risk again. You
then have to re-triage those rows: re-read each one, decide its new verdict,
and write the test that defends it.

Most of these rows are recorded as `n/a`. Five are recorded as `already-safe`
instead, because wired has the part of the code they touch that exists today:

- V-0223 and V-0547: a test pins that part (the ECN count check, and
  case-insensitive name matching). The missing part (the self-marked CE
  probe, RFC 4518 string normalisation) has no test.
- V-0378 and V-0386: structural, no test. The server's certificate is only
  ever sent encrypted; with no client certificates, there is no client
  identity to leak.
- V-0711: structural, no test. wired never decrypts with RSA, so the timing
  attack on RSA decryption has no code path.

Where the consequence column says **re-triage if added**, the attack cannot
happen today, and adding the feature means re-triaging those rows. The other
cells say what the gap means for a deployment. For the rest of the security
records, see the [security index](README.md).

TLS terms used in the table:

- *TLS 1.3* is the handshake that QUIC uses to agree on keys and to
  authenticate the server. QUIC carries the TLS messages inside its own
  packets (see the
  [TLS handshake guide](https://hakkadaikon.github.io/wired/guide/en/tls/handshake/)).
- *CertificateVerify* is the handshake message where a peer signs to prove
  it owns its certificate. A certificate chain carries its own, separate
  signatures (each CA signs the certificate below it).
- *ECDHE* and *DHE* are the two families of key-exchange methods
  (elliptic-curve and finite-field Diffie-Hellman).
- A *PSK* (pre-shared key) resumes or starts a session without a full
  handshake. The *Selfie* attack reflects an endpoint's own PSK handshake back
  at it, so it ends up talking to itself; it needs an external PSK that one
  endpoint uses in both the client and the server role.
- *Revocation* is how a certificate is withdrawn before it expires.

ECN terms used in the table: *ECN* (Explicit Congestion Notification) lets
routers mark a packet "congestion experienced" (CE) instead of dropping it,
and the receiver reports the counts of marks it saw.

- A *self-marked CE probe* means the sender marks some of its own packets CE
  to test whether the peer reports them honestly. wired cannot do this: it
  sets the ECN bits for the whole socket (`IP_TOS`), not for each packet sent
  (`cmsg`).
- The *count floor* (RFC 9000 13.4.2.1) makes the sender check that the
  peer's reported counts rise by at least the number of packets newly
  acknowledged. A peer that drops CE reports fails this check, and wired then
  turns ECN off and relies on loss detection. A peer that relabels CE as an
  ordinary mark passes it; catching that would need the self-marked probe.

The MoQT row's hook is how your application approves each subscription; see
the [authorization guide](https://hakkadaikon.github.io/wired/guide/en/moqt/authorize/).

| Feature absent | Ledger rows | Consequence for a deployment |
|---|---|---|
| Encrypted Client Hello (ECH, draft-ietf-tls-esni) | V-0238, V-0240 | re-triage if added |
| ECDSA P-521 for CertificateVerify (supported: P-256, RSA-PSS, Ed25519) | V-0247 | a peer cannot sign CertificateVerify with `ecdsa_secp521r1_sha512`; P-521-signed certificate chains do verify (since 2026-10-10) |
| Client certificate authentication (CertificateRequest / mutual TLS) | V-0268, V-0330, V-0377, V-0383, V-0378, V-0386 | only the server is authenticated; the client's identity must come from the application layer |
| Finite-field DHE groups (only X25519 / P-256 ECDHE) | V-0270 | re-triage if added |
| RSA-PSK / RSA key transport (RSA is verify-only) | V-0271, V-0274, V-0660, V-0696, V-0711, V-0739, V-0741 | re-triage if added |
| CBC-mode cipher suites (only AES-GCM and ChaCha20-Poly1305) | V-0285, V-0759 | re-triage if added |
| certificate_compression extension (RFC 8879) | V-0299 | re-triage if added |
| External PSK (only server-sealed resumption tickets) | V-0300 | only ticket resumption; Selfie-style reflection has no surface |
| Revocation checking: CRL, OCSP, OCSP stapling, AIA / CRL-DP fetching | V-0324, V-0528, V-0531, V-0557, V-0560, V-0573, V-0620, V-0621 | revocation is an operator concern (short-lived certificates, out-of-band rotation) |
| TLS 1.2 and earlier: extended_master_secret, middlebox compatibility mode, SSLv2 CLIENT-HELLO | V-0347, V-0360, V-0366 | wired speaks only TLS 1.3, and only inside QUIC |
| Client-side retry-with-different-parameters loop | V-0351 | re-triage if added |
| ECN self-marked CE probe (socket-wide IP_TOS only, no per-send cmsg) | V-0223 | suppressed CE reports are still caught by the RFC 9000 13.4.2.1 count floor |
| DSA | V-0576, V-0655, V-0677, V-0687 | re-triage if added |
| Curve448 / Ed448 / Ed25519ctx-ph context parameter | V-0718, V-0729, V-0730, V-0732, V-0734, V-0766 | re-triage if added |
| Init/Update/Finish (streaming) signature API (single-buffer only) | V-0736, V-0737 | re-triage if added |
| Private key generation (keys are supplied as raw seeds / scalars) | V-0747 | re-triage if added |
| PKCS#7 / CMS parsing | V-0526 | re-triage if added |
| RFC 4518 DN string normalisation in name constraints (exact-bytes match for the non-directoryName forms) | V-0547 | re-triage if added |
| Signed Certificate Timestamps / Certificate Transparency | V-0549 | re-triage if added |
| rfc822Name (email) GeneralName in SAN / name constraints | V-0556 | re-triage if added |
| Composite / multi-algorithm signatures (draft PKIX CompositeSignature) | V-0568 | re-triage if added |
| HTTP/1.1 backend connections (no proxy role) | V-0435 | re-triage if added |
| HTTP/3 server push (PUSH_PROMISE) | V-0446 | re-triage if added |
| QPACK intermediary role (one dynamic table per connection, no forwarding) | V-0468 | re-triage if added |
| Client-side WebTransport session opening | V-0510 | re-triage if added |
| MoQT authorization token schemes (CAT / Privacy Pass); the token is decoded and handed to the authorize hook | V-0794 | the relay decides authorization through wired_moqt_hub.authorize_subscribe |

The table lists 57 ledger rows in 26 groups. Every other ledger row is either
defended (fixed or already-safe) or `n/a` for a reason that does not depend
on a missing feature, such as an informational or design-level row.

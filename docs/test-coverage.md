[Docs](README.md) › Test Coverage

# Test Coverage by Specification

> **At a glance** — all 42 implemented specs are exercised by the unit
> suite (460+ test files, every commit); 19 of them are additionally pinned
> to official/golden vectors; three wire-facing parsers are fuzzed nightly;
> and interop against real independent clients has proven the QUIC
> `handshake` / `transfer` / `http3` testcases (vs quic-go) and 4 of 7
> WebTransport testcases (vs webtransport-go). This page lists exactly what
> has and hasn't been demonstrated, per spec. Results as of 2026-07.

Legend:

- `[x]` — demonstrated by a passing test
- `[~]` — exercised indirectly (the code path runs, but no test targets
  that spec by name / no dedicated interop case)
- `[ ]` — not demonstrated yet

## The four evidence tiers

1. **Unit tests** — `tests/` (unity build, assertions on) runs on every
   commit and in CI. Round-trips, state machines, boundary values, and
   malformed-input rejection.
2. **Official / golden vectors** — where a spec publishes test vectors, the
   implementation is pinned to them (RFC appendix vectors, NIST KATs, real
   OpenSSL-generated certificate chains).
3. **Fuzzing** — three libFuzzer+ASan harnesses (packet header, QPACK,
   X.509), run nightly in CI.
4. **Interop** — [quic-interop-runner](https://github.com/quic-interop/quic-interop-runner)
   against independent client implementations. This is the only tier that
   proves wire compatibility: a self-loopback test cannot catch a spec
   misreading shared by both ends.

## Interop results

### QUIC testcases (server: wired · client: quic-go)

- [x] `handshake` — connection establishment
- [x] `transfer` — file download over streams
- [x] `http3` — parallel HTTP/3 GETs (3 streams, 500 KB bodies)
- [ ] `longrtt` — not yet run
- [ ] `chacha20` — not yet run
- [ ] `multiplexing` — not yet run
- [ ] `retry` — not yet run
- [ ] `resumption` — not yet run
- [ ] `zerortt` — not yet run
- [ ] `blackhole` — not yet run
- [ ] `keyupdate` — not yet run
- [ ] `ecn` — not yet run
- [ ] `amplificationlimit` — not yet run
- [ ] `handshakeloss` — not yet run
- [ ] `transferloss` — not yet run
- [ ] `handshakecorruption` — not yet run
- [ ] `transfercorruption` — not yet run
- [ ] `ipv6` — not yet run
- [ ] `v2` — not yet run
- [ ] `rebind-port` / `rebind-addr` — not yet run
- [ ] `connectionmigration` — not yet run
- [ ] `goodput` / `crosstraffic` (measurements) — not yet run

### WebTransport testcases (server: wired · client: webtransport-go)

- [x] `handshake` — Extended CONNECT session establishment
- [x] `transfer-unidirectional-receive` — server pushes files on uni streams
- [x] `transfer-bidirectional-receive` — server replies on bidi streams
- [x] `transfer-datagram-receive` — server pushes over DATAGRAMs
- [ ] `transfer-unidirectional-send` — client upload stalls partway
  (QUIC-level flow control and ACKs verified correct on both sides via
  qlog; the client stops writing mid-transfer — under investigation)
- [ ] `transfer-bidirectional-send` — same stall
- [ ] `transfer-datagram-send` — same stall

Two real interop bugs were found and fixed by these runs (a QPACK literal
field-line buffer split and a WebTransport stream-signal length bug), which
is exactly what this tier exists for.

## Per-spec status

### QUIC core

**RFC 9000 — QUIC Transport**
- [x] Unit — 77 test files: varint/header/frame codecs, stream and
  connection state machines, flow control, full loopback handshake
- [x] Vectors — Appendix A varint sample encodings (`varint_test.c`)
- [x] Fuzzing — invariant header parser + coalesced-datagram splitter
  (`fuzz/fuzz_header.c`)
- [x] Interop — `handshake` / `transfer` / `http3` green vs quic-go

**RFC 9001 — Using TLS to Secure QUIC**
- [x] Unit — 61 test files: key derivation, packet & header protection
  (AES and ChaCha), key update, Retry integrity tag
- [x] Vectors — Appendix A Initial secrets (DCID `8394c8f03e515708`) and
  §5.8 Retry key/nonce match exactly (`initial_test.c`)
- [x] Interop — every green interop case crosses this on the wire

**RFC 9002 — Loss Detection and Congestion Control**
- [x] Unit — 28 test files: RTT estimation, packet/time-threshold loss,
  PTO backoff, retransmission selection, in-flight accounting
- [~] Interop — exercised under the simulated 10 Mbps / 30 ms link in every
  transfer, but the loss-specific testcases (`transferloss` etc.) have not
  been run (spec publishes no official vectors)

**RFC 8999 — Version-Independent Properties**
- [x] Unit — invariant header parsing, Version Negotiation packets
- [x] Fuzzing — shared with the RFC 9000 header harness
- [x] Interop — long/short header interop implied by every green case

### QUIC extensions

**RFC 9221 — Unreliable Datagram Extension**
- [x] Unit — 12 test files: DATAGRAM frame codec, transport parameter,
  delivery/violation checks
- [x] Interop — `transfer-datagram-receive` green (WebTransport rides
  QUIC DATAGRAMs)

**RFC 9287 — Greasing the QUIC Bit**
- [x] Unit — grease TP, bit randomization, reset-bit handling
- [ ] Interop — no runner testcase exists for it

**RFC 9368 — Compatible Version Negotiation**
- [x] Unit — version_information TP, selection rules, downgrade defense
- [ ] Interop — `v2` testcase not yet run

**RFC 9369 — QUIC Version 2**
- [x] Unit — v2 packet types, v2 salts/labels, v1↔v2 switching
- [x] Vectors — §3.3.3 v2 Retry key/nonce and v2 initial salts
- [ ] Interop — `v2` testcase not yet run

**RFC 9308 / RFC 9312 — Applicability / Manageability (informational)**
- [~] Unit — guidance documents; the implementable slices (0-RTT policy,
  keep-alive, spin-bit observation) have dedicated tests via their modules

**RFC 8899 — Packetization Layer PMTU Discovery**
- [~] Unit — the DPLPMTUD probe/ack/ceiling state machine is tested
  (`pmtu_test.c`), without citing the RFC by number

### TLS and PKI

**RFC 8446 — TLS 1.3**
- [x] Unit — 35 test files: handshake state machine, transcript hash, key
  schedule, message build/parse, CertificateVerify
- [x] Vectors — golden handshake fixtures with a real Ed25519 leaf
  (`fullhs_golden.h`), RSA CertificateVerify transcript
- [x] Interop — every green case completes a real TLS 1.3 handshake

**RFC 5280 — X.509 / PKI**
- [x] Unit — 17 test files: DER parsing, path validation, CA-bit and
  validity checks, malformed rejection
- [x] Vectors — real OpenSSL-generated chains as golden fixtures
  (P-256, P-384, RSA chains)
- [x] Fuzzing — certificate parser + TBS field extractor (`fuzz/fuzz_x509.c`)
- [x] Interop — the runner's CA-issued chain is served and accepted

**RFC 5480 / RFC 5758 — EC public keys & signature OIDs in certificates**
- [x] Unit — EC SubjectPublicKeyInfo and ecdsa-with-SHA256 OID handling
  (5758 via `sigalg_test.c`, uncited)
- [~] Interop — exercised whenever the interop chain's P-256 key is parsed

**RFC 8410 — Ed25519/X25519 algorithm identifiers**
- [x] Unit — Ed25519 SPKI and self-signed certificate encoding
- [ ] Interop — interop runs used ECDSA certs, not Ed25519

**RFC 6066 — TLS extensions (SNI)**
- [x] Unit — SNI codec and TLS-driver handling
- [~] Interop — clients send SNI in every green run; no dedicated case

**RFC 6125 — service identity verification**
- [x] Unit — SAN/hostname matching and rejection (the API is
  caller-invoked; see [Security](security.md))

**RFC 7301 — ALPN**
- [x] Unit — negotiation and EncryptedExtensions build
- [x] Interop — `h3` negotiated in every green case

**RFC 8017 — PKCS #1 (RSA)**
- [x] Unit — v1.5 verify, RSA-PSS/MGF1, known-answer constants
- [ ] Interop — interop runs used ECDSA certs, not RSA

### Cryptographic primitives

All primitives are pure functions verified against published vectors; they
are also exercised implicitly inside every loopback and interop handshake.

- [x] **RFC 8439** ChaCha20-Poly1305 — A.1 / §2.5.2 vectors, AEAD seal-open
- [x] **RFC 7748** X25519 — §5.2 vectors 1 & 2; also live in every interop
  key exchange
- [x] **RFC 8032** Ed25519 — §7.1 vectors plus tampered-signature rejection
- [x] **RFC 6979** deterministic ECDSA — A.2.5 P-256/SHA-256 vector; live
  in every interop CertificateVerify
- [x] **RFC 5869** HKDF — Appendix A.1 vector; live in every handshake
- [x] **FIPS 197** AES — Appendix B/C.1 known-answer tests
- [x] **SP 800-38D** GCM — NIST test case 4 (with AAD), tag-mismatch
  rejection; live in every interop packet
- [x] **FIPS 186-4** ECDSA P-256 — sign/verify via the 6979 vectors and
  golden chains
- [x] **FIPS 180-4** SHA-2 — NIST sample vectors (SHA-256/384)
- [x] **FIPS 198-1** HMAC — RFC 4231 HMAC-SHA-256 vectors
  (`hmac_test.c`, cited by the companion RFC rather than FIPS number)
- [~] **RFC 6090** EC arithmetic — P-256 field ops tested with hex known
  answers, without citing the RFC by number

### HTTP/3 and QPACK

**RFC 9114 — HTTP/3**
- [x] Unit — 28 test files: frame/settings/request-response codecs,
  control stream, server request loop, malformed rejection (spec defines
  no official vectors)
- [x] Interop — `http3` green vs quic-go; the WebTransport cases ride it

**RFC 9110 — HTTP semantics**
- [x] Unit — method/status handling at the server-loop level
- [~] Interop — exercised by every HTTP/3 request in green runs

**RFC 9204 — QPACK**
- [x] Unit — 23 test files: static & dynamic tables, prefix/integer/
  literal encodings, instruction decode
- [x] Vectors — spec-derived static-table and field-line examples
- [x] Fuzzing — indexed field-line decoder with a live dynamic table
  (`fuzz/fuzz_qpack.c`)
- [x] Interop — every green HTTP/3 exchange decodes real quic-go QPACK

**RFC 7541 — HPACK (Huffman/integers reused by QPACK)**
- [x] Unit — Huffman and integer-prefix round-trips against the RFC's own
  examples
- [x] Interop — exercised by every interop header block

**RFC 9218 — Extensible priorities**
- [x] Unit — priority field parsing, PRIORITY_UPDATE handling
- [ ] Interop — no green case exercises priorities

### WebTransport

**draft-ietf-webtrans-http3 (draft-15)**
- [x] Unit — 17 test files: session state machine, stream signals,
  capsules, error-code mapping, multi-session management
- [x] Interop — `handshake` + all three `*-receive` cases green vs
  webtransport-go; the three `*-send` cases still fail (see above)

**RFC 9220 — Extended CONNECT in HTTP/3**
- [x] Unit — `:protocol` pseudo-header, SETTINGS_ENABLE_CONNECT_PROTOCOL
- [x] Interop — every WebTransport session establishment crosses it

**RFC 9297 — HTTP Datagrams and Capsules**
- [x] Unit — datagram/capsule envelope codecs
- [x] Interop — `transfer-datagram-receive` green

### IP/UDP foundations

These headers are built by wired itself only on the AF_XDP path; the interop
runs used kernel UDP sockets, so they are unit-tested but not interop-proven.

- [x] **RFC 1071** internet checksum — the RFC's own worked example
  (`net_test.c`)
- [~] **RFC 768** UDP header — build + checksum corrupt-reject tested,
  without citing the RFC by number
- [~] **RFC 791** IPv4 header — same, in the same test file
- [ ] Interop over wired's own IPv4/UDP framing (AF_XDP) — not yet run
  against a real client

## Honest summary of the gaps

- 19 of 22 QUIC interop testcases (plus both measurements) have not been
  attempted yet; only quic-go and webtransport-go have been used as peers.
- The three WebTransport `*-send` interop cases have never passed; the
  QUIC layer has been verified blameless via qlog, and the investigation
  is parked at the client's send scheduling.
- Loss/corruption behavior (RFC 9002 edge paths) is unit-tested but has no
  interop demonstration.
- Ed25519 and RSA certificate paths, priorities (RFC 9218), version 2
  (RFC 9369), and QUIC-bit greasing (RFC 9287) are fully unit-tested but
  have never been exercised against a real peer.
- The AF_XDP path's self-built IPv4/UDP framing has no interop run.

---

**Next:** [Implemented Specifications](arch/rfcs.md) — what each spec is
for. ([all docs](README.md))

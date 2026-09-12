# Vulnerability ledger

One row per vulnerability class or advisory the SDK's protocols are exposed
to. Method: `docs/superpowers/specs/2026-09-12-vuln-and-perf-audit-plan.md`.
Machine check: `python3 scripts/vulnaudit/ledger_check.py docs/security/vuln-ledger.md`.

Row grammar (one row = one entry, continuation lines indented):

```
- [ ] V-0001 <source id> (<product|RFC section>) <one-line class/summary>
      ours: <src path or n/a> — verdict: ?|fixed|already-safe|n/a — test: <name> — commit: <sha> — perf: <lane delta or n/a>
```

- `[ ]` untriaged, `[~]` triaged (verdict + planned test), `[x]` closed.
- A row may be `[x]` only with `verdict: fixed` + test + commit, or
  `verdict: already-safe` + test + commit (the pinning test), or
  `verdict: n/a` + a reason in place of the test.
- Update the row in the same commit that closes it.

## Summary

Phase 1 (2026-09-12): 836 rows from six raw sources (spec paragraphs 302 +
130 + 4, peer-implementation advisories 62 + 56 + 223, literature 41, mp4
parsers 22, npm audits 20; deduplicated by id/alias). Per-source coverage
tables live with the raw data (tasks/vuln/raw/*.coverage.md). Known gaps:
X.690 not directly fetchable (covered via RFC 5280 §8 / RFC 7468), ~35
Bouncy Castle 2026 advisories without fetched detail, NVD bulk queries
rate-limited (vendor pages and GitHub Advisory used instead).

Counts: `python3 scripts/vulnaudit/ledger_check.py docs/security/vuln-ledger.md`.

## QUIC transport (RFC 9000/9001/9002/9368/9369/9287)

- [ ] V-0002 CVE-2024-52811 (ngtcp2) integer-overflow: ACK ranges are not validated before being written to the qlog output, causing an integer underflow in ACK fram
      ours: ACK frame range validation before qlog/debug serialization (integer underflow on unvalidated ACK ranges) — verdict: ? — test: — commit: — perf: —
- [ ] V-0003 CVE-2026-40170 (ngtcp2) oob-write: ngtcp2_qlog_parameters_set_transport_params() serializes peer transport parameters into a fixed 1024-byte stac
      ours: transport parameter decode -> qlog serialization into fixed-size stack buffer (no length check against buffer capacity) — verdict: ? — test: — commit: — perf: —
- [ ] V-0004 L-NGTCP2-001 (ngtcp2) hash-dos: NCC Group's multi-implementation QUIC hash-DoS advisory lists ngtcp2's example server (not the library core) a
      ours: connection ID lookup table keyed by attacker-chosen SCID/DCID without a keyed/randomized hash — verdict: ? — test: — commit: — perf: —
- [ ] V-0005 GHSA-47m2-4cr7-mhcw (quic-go) nil-deref/crash-on-frame: A panic can be triggered by receiving a HANDSHAKE_DONE frame prematurely (before the handshake actually comple
      ours: HANDSHAKE_DONE frame handler must reject receipt before handshake-confirmed state, on both client and server roles — verdict: ? — test: — commit: — perf: —
- [ ] V-0006 GHSA-j972-j939-p2v3 (quic-go) nil-deref/crash-on-frame: Nil-pointer dereference in path-probe loss recovery logic, triggerable by a peer during connection migration p
      ours: path-probe/PATH_CHALLENGE loss-detection bookkeeping during connection migration (probe entry missing before recovery timer fires) — verdict: ? — test: — commit: — perf: —
- [ ] V-0007 GHSA-c33x-xqrf-c478 (quic-go) resource-exhaustion-pre-handshake: The connection ID issuance/retirement mechanism can be abused by a peer to make the endpoint allocate and reta
      ours: NEW_CONNECTION_ID / RETIRE_CONNECTION_ID bookkeeping must cap the number of active/retired CIDs tracked per connection — verdict: ? — test: — commit: — perf: —
- [ ] V-0008 GHSA-ppxx-5m9h-6vxf (quic-go) resource-exhaustion-pre-handshake: An attacker can cause memory exhaustion by sending large numbers of PATH_CHALLENGE frames while never allowing
      ours: path validation (PATH_CHALLENGE/PATH_RESPONSE) state table must be bounded per connection regardless of how many distinct paths a peer probes — verdict: ? — test: — commit: — perf: —
- [ ] V-0009 GHSA-3q6m-v84f-6p9h (quic-go) nil-deref/crash-on-frame: Starting in v0.37.0, remote peers could trigger a nil-pointer dereference leading to a panic when the implemen
      ours: packet-number-space teardown (dropping the Handshake pn space) must not race with a still-in-flight process on that space — verdict: ? — test: — commit: — perf: —
- [ ] V-0010 CVE-2022-30591 (quic-go) resource-exhaustion-pre-handshake: quic-go through v0.27.0 allows remote attackers to cause denial of service (CPU consumption) via a Slowloris-s
      ours: pre-handshake connection acceptance / idle-timeout enforcement for slow-trickling peers — verdict: ? — test: — commit: — perf: —
- [ ] V-0011 CVE-2026-11941 (quiche) use-after-free: Use-after-free in the FFI connection-ID iterator functions exposed by quiche's C API, reachable when a caller 
      ours: quiche FFI connection-ID iterator lifetime vs. connection object mutation/free ordering — verdict: ? — test: — commit: — perf: —
- [ ] V-0012 CVE-2026-12707 (quiche) resource-exhaustion-pre-handshake: Unbounded queuing of post-handshake path-migration events allows a peer to grow migration-related state withou
      ours: post-handshake path migration event queue must be bounded per connection — verdict: ? — test: — commit: — perf: —
- [ ] V-0013 GHSA-m3hh-f9gh-74c2 (quiche) resource-exhaustion-pre-handshake: Sending packets containing RETIRE_CONNECTION_ID frames can trigger an infinite loop in quiche's connection-ID 
      ours: RETIRE_CONNECTION_ID processing loop must have a termination bound independent of attacker-supplied sequence numbers — verdict: ? — test: — commit: — perf: —
- [ ] V-0014 CVE-2025-4820 (quiche) optimistic-ack: Incorrect congestion-window growth via ACK manipulation: an attacker (in an off-path or on-path position, or a
      ours: ACK frame range validation against the largest sent packet number / congestion controller cwnd growth gated on genuinely-acknowledged bytes — verdict: ? — test: — commit: — perf: —
- [ ] V-0015 CVE-2025-4821 (quiche) optimistic-ack: Congestion-window overflow from malformed/manipulated ACK frames, related to CVE-2025-4820, allowing an attack
      ours: congestion controller cwnd update arithmetic must not overflow/wrap when fed attacker-influenced ACK'd-bytes values — verdict: ? — test: — commit: — perf: —
- [ ] V-0016 CVE-2024-1765 (quiche) resource-exhaustion-pre-handshake: Unlimited allocation of 1-RTT CRYPTO frames allows a peer to force unbounded memory allocation before the hand
      ours: CRYPTO frame reassembly buffer must have a hard cap independent of the advertised transport parameters, applied pre-handshake-confirmation — verdict: ? — test: — commit: — perf: —
- [ ] V-0017 CVE-2024-1410 (quiche) resource-exhaustion-pre-handshake: Unbounded storage of connection-ID-retirement-related information, allowing a peer to grow endpoint state with
      ours: retired-connection-ID bookkeeping (sequence numbers awaiting NEW_CONNECTION_ID retirement ack) must be capped — verdict: ? — test: — commit: — perf: —
- [ ] V-0018 CVE-2023-6193 (quiche) resource-exhaustion-pre-handshake: Unbounded queuing of path-validation messages (PATH_CHALLENGE/PATH_RESPONSE) allows a peer to grow endpoint st
      ours: path validation message queue must be bounded per connection (predecessor of the quic-go GHSA-ppxx-5m9h-6vxf class bug) — verdict: ? — test: — commit: — perf: —
- [ ] V-0019 GHSA-4w2j-m93h-cj5j (quinn-proto) resource-exhaustion-pre-handshake: Remote memory exhaustion in quinn-proto from unbounded out-of-order stream data reassembly: a peer sending str
      ours: stream receive-buffer reassembly (out-of-order chunk storage) must be bounded by the stream/connection flow-control window, not by the number of distinct out-of-order ranges — verdict: ? — test: — commit: — perf: —
- [ ] V-0020 CVE-2026-31812 (quinn-proto) resource-exhaustion-pre-handshake: Remote unauthenticated attackers can cause denial of service by sending crafted QUIC Initial packets with malf
      ours: transport parameter decoder must reject malformed/out-of-range values without panicking, before handshake/connection is confirmed — verdict: ? — test: — commit: — perf: —
- [ ] V-0021 CVE-2024-45311 (quinn-proto) retry-token: Calling retry() on unvalidated connections in quinn-proto 0.11+ can trigger panics when receiving duplicate In
      ours: server-side Retry issuance path (Endpoint::retry) must handle duplicate/racing Initial packets and decryption failures without panicking — verdict: ? — test: — commit: — perf: —
- [ ] V-0022 CVE-2023-42805 (quinn-proto) nil-deref/crash-on-frame: Receiving unknown/unrecognized QUIC frame types in a packet could result in a panic instead of the frame being
      ours: frame-type dispatch table/switch must have a safe default case for unknown frame types (reserved/grease frame types per RFC 9000) — verdict: ? — test: — commit: — perf: —
- [ ] V-0023 CVE-2026-62815 (msquic) use-after-free: Use-after-free vulnerability: network path creation and removal triggered by incoming packets can lead to poin
      ours: network path object lifetime vs. path-creation/removal triggered by PATH_CHALLENGE/migration packet processing (path table entry freed while still referenced) — verdict: ? — test: — commit: — perf: —
- [ ] V-0024 CVE-2026-32179 (msquic) integer-overflow: Improper input validation in MsQuic allows privilege elevation over the network, stemming from an integer unde
      ours: ACK frame range/gap decoding arithmetic (integer underflow on ACK range or gap fields) — verdict: ? — test: — commit: — perf: —
- [ ] V-0025 CVE-2024-26190 (msquic) resource-exhaustion-pre-handshake: The MsQuic server leaks memory during transport parameter decoding, continuing until no more memory is availab
      ours: transport parameter decode path must free/reuse intermediate allocations on both success and rejection paths — verdict: ? — test: — commit: — perf: —
- [ ] V-0026 CVE-2023-36435 (msquic) resource-exhaustion-pre-handshake: Memory leak vulnerability in MsQuic servers causes continuous memory depletion when processing multiple decode
      ours: transport parameter decode path memory lifecycle (earlier instance of the same class fixed again in CVE-2024-26190) — verdict: ? — test: — commit: — perf: —
- [ ] V-0027 CVE-2023-38171 (msquic) nil-deref/crash-on-frame: A remote denial-of-service vulnerability in MsQuic causes server applications to crash when processing special
      ours: packet-processing dispatch path missing a null-check before dereferencing a connection/stream object derived from attacker-controlled packet contents — verdict: ? — test: — commit: — perf: —
- [ ] V-0028 CVE-2025-24947 (lsquic) hash-dos: A hash-collision vulnerability in the hash table managing connections within LSQUIC (before 4.2.0) enables rem
      ours: connection-ID-keyed lookup table (SCID hash table) must use a keyed/randomized hash seeded per-process, not a predictable hash of attacker-chosen bytes — verdict: ? — test: — commit: — perf: —
- [ ] V-0029 CVE-2025-54939 (lsquic) resource-exhaustion-pre-handshake: LiteSpeed QUIC (LSQUIC) before 4.3.1 has a memory leak in lsquic_engine_packet_in, the top-level packet ingest
      ours: packet-ingestion entry point (lsquic_engine_packet_in equivalent) must free all intermediate buffers on every exit path including error/reject paths — verdict: ? — test: — commit: — perf: —
- [ ] V-0030 CVE-2020-24944 (picoquic) resource-exhaustion-pre-handshake: picoquic (before 2020-07-03) allows attackers to cause denial of service (infinite loop) via a crafted QUIC fr
      ours: frame-parsing loop must have a monotonically-advancing cursor guarantee independent of the frame type/contents (a malformed frame must not stall the parse loop) — verdict: ? — test: — commit: — perf: —
- [ ] V-0031 CVE-2025-24946 (picoquic) hash-dos: Weak hash function in picoquic connection management enables remote attackers to cause significant CPU load th
      ours: connection-ID-keyed lookup table (SCID hash table) must use a keyed/randomized hash — verdict: ? — test: — commit: — perf: —
- [ ] V-0032 CVE-2026-10740 (s2n-quic) resource-exhaustion-pre-handshake: Unbounded memory allocation in the CRYPTO frame reassembler in s2n-quic before 1.8.2 may allow an unauthentica
      ours: CRYPTO frame reassembly buffer during Initial/Handshake must have a hard cap enforced pre-handshake, same class as quiche CVE-2024-1765 — verdict: ? — test: — commit: — perf: —
- [ ] V-0033 GHSA-475v-pq2g-fp9g (s2n-quic) resource-exhaustion-pre-handshake: Potential denial of service via crafted stream frames in s2n-quic.
      ours: stream frame handling path (no further public detail beyond advisory title) -- treat as generic STREAM frame DoS until upstream detail found — verdict: ? — test: — commit: — perf: —
- [ ] V-0034 GHSA-rfhg-rjfp-9q8q (s2n-quic) migration: Potential denial of service after connection migration in s2n-quic.
      ours: post-migration connection state handling (no further public detail beyond advisory title) — verdict: ? — test: — commit: — perf: —
- [ ] V-0035 CVE-2021-24029 (mvfst) nil-deref/crash-on-frame: A 'packet of death' scenario is possible in mvfst via a specially crafted message during a QUIC session, causi
      ours: assertion in packet/frame processing reachable by a peer-controlled malformed message (specific frame type not public) — verdict: ? — test: — commit: — perf: —
- [ ] V-0036 CVE-2025-30403 (mvfst) oob-write: A heap-buffer-overflow vulnerability is possible in mvfst via a specially crafted message during a QUIC sessio
      ours: heap buffer overflow reachable via a peer-controlled malformed message during an active QUIC session (specific frame/parser not public in NVD description) — verdict: ? — test: — commit: — perf: —
- [ ] V-0037 CVE-2026-1788 (xquic) oob-write: Out-of-bounds write vulnerability in the XQUIC server packet-processing module on Linux, allowing buffer manip
      ours: packet processing module buffer bounds check (specific frame/field not detailed in NVD) — verdict: ? — test: — commit: — perf: —
- [ ] V-0038 CVE-2025-47200 (xquic) hash-dos: Server-side connection lookup hash tables in xquic are vulnerable to crafted Source Connection ID collisions, 
      ours: connection-ID-keyed lookup table (SCID hash table) must use a keyed/randomized hash — verdict: ? — test: — commit: — perf: —
- [ ] V-0039 GHSA-mfv9-vpqc-fc57 (neqo-transport) nil-deref/crash-on-frame: A remote attacker can trigger a panic by sending crafted combinations of STOP_SENDING and STREAM frames for th
      ours: stream state machine must handle STOP_SENDING arriving concurrently/interleaved with STREAM data on the same stream ID without panicking — verdict: ? — test: — commit: — perf: —
- [ ] V-0040 GHSA-95mj-575f-47cq (neqo-transport) oob-read: SelfEncrypt::open() did not validate ciphertext length before use, leading to a safe out-of-bounds-triggered c
      ours: address-validation token AEAD-sealed-box open() must validate the minimum ciphertext length (nonce+tag) before slicing — verdict: ? — test: — commit: — perf: —
- [ ] V-0041 GHSA-56c6-rfrf-rh4r (neqo-transport) retry-token: A remote attacker can trigger a panic in the server by sending an unauthorized NEW_TOKEN frame after handshake
      ours: server-side NEW_TOKEN frame receipt handling (a server must never receive NEW_TOKEN; must reject with PROTOCOL_VIOLATION, not panic) -- RFC 9000 19.7 — verdict: ? — test: — commit: — perf: —
- [ ] V-0042 GHSA-jfv6-x22w-grhf (neqo-transport) integer-overflow: transport/fc.rs: panic attempting to send MAX_DATA with a value larger than the max varint, i.e. flow-control 
      ours: MAX_DATA/flow-control credit accumulation must saturate at the varint maximum (2^62-1) rather than overflow/panic when encoding — verdict: ? — test: — commit: — perf: —
- [ ] V-0043 GHSA-hvhj-4r52-8568 (neqo-transport) integer-overflow: Subtraction underflow when parsing Retry packets, i.e. a length/offset computation on an attacker-controlled R
      ours: Retry packet parsing length arithmetic (e.g. computing the Retry Integrity Tag offset) must check for underflow before subtracting — verdict: ? — test: — commit: — perf: —
- [ ] V-0044 GHSA-5m9j-vr32-g7j5 (neqo-transport) resource-exhaustion-pre-handshake: transport/frame.rs: unbounded memory allocation based on unsanitized network input.
      ours: frame decode path allocates a buffer sized directly from an attacker-controlled length field without an upper bound — verdict: ? — test: — commit: — perf: —
- [ ] V-0045 CVE-2025-6703 (neqo-transport) nil-deref/crash-on-frame: Improper input validation vulnerability in Mozilla neqo leads to an unexploitable crash; affects neqo from 0.4
      ours: generic input-validation panic path (NVD description does not specify which frame/field); likely overlaps with one of the GHSA-listed neqo advisories above but NVD gives no cross-reference — verdict: ? — test: — commit: — perf: —
- [ ] V-0046 CVE-2024-45396 (quicly) nil-deref/crash-on-frame: Quicly up to commit d720707 is susceptible to a denial-of-service attack via an assertion failure that crashes
      ours: assertion reachable via peer-controlled input (specific trigger not detailed in NVD; see GHSA-mp3c-h5gg-mm6p for likely match) — verdict: ? — test: — commit: — perf: —
- [ ] V-0047 CVE-2025-61684 (quicly) nil-deref/crash-on-frame: Quicly is susceptible to a denial-of-service attack prior to commit d9d3df6a8530a102b57d840e39b0311ce5c9e14e v
      ours: assertion reachable via peer-controlled input; likely corresponds to GHSA-wr3c-345m-43v9 — verdict: ? — test: — commit: — perf: —
- [ ] V-0048 CVE-2026-44433 (quicly) resource-exhaustion-pre-handshake: Prior to commit 8b178e6, an adversarial peer could send a STREAM frame causing memory exhaustion and denial of
      ours: STREAM frame receive-buffer accounting must be bounded regardless of stream ID / offset chosen by the peer; likely corresponds to GHSA-f7qr-4p37-9gx9 (memory exhaustion) — verdict: ? — test: — commit: — perf: —
- [ ] V-0049 CVE-2026-44434 (quicly) nil-deref/crash-on-frame: Prior to commit dccf5d4, Quicly is vulnerable to stateless-reset injection through lack of packet-origin/entry
      ours: stateless reset token validation must check the token against the connection's actually-issued reset token before honoring it, and the reset-triggering packet must be checked against expected origin; likely corresponds to GHSA-899f-49jq-pfh8 — verdict: ? — test: — commit: — perf: —
- [ ] V-0050 CVE-2026-44435 (quicly) nil-deref/crash-on-frame: An assertion failure is raised when handshake messages exceed 32KB, causing denial of service.
      ours: CRYPTO frame / handshake message reassembly must reject (not assert on) a peer-supplied handshake message exceeding the implementation's buffer limit; likely corresponds to GHSA-wr3c-345m-43v9 or GHSA-mp3c-h5gg-mm6p — verdict: ? — test: — commit: — perf: —
- [ ] V-0051 CVE-2026-44436 (quicly) oob-write: Prior to commit 8b178e6, Quicly is vulnerable to denial of service through connection-state corruption via ove
      ours: connection ID length must be validated against RFC 9000's max CID length (20 bytes) before being used to size/copy into a fixed connection-state buffer; likely corresponds to GHSA-v55w-59qx-2v78 (Connection state corruption) — verdict: ? — test: — commit: — perf: —
- [ ] V-0052 CVE-2023-50247 (quicly) resource-exhaustion-pre-handshake: State-exhaustion denial of service in Quicly: a remote attacker can progressively increase memory consumption,
      ours: general per-connection state growth bound (reporter: Marten Seemann; framed as an RFC 9000 spec-level gap, so also cross-check against S-9000 Security Considerations entries for connection state exhaustion) — verdict: ? — test: — commit: — perf: —
- [ ] V-0053 CVE-2017-15407 (chromium (QUIC)) oob-write: Out-of-bounds write in the QUIC networking stack in Google Chrome prior to 63.0.3239.84 allowed a remote attac
      ours: transport/* frame/packet decode paths that write into fixed-size receive buffers — verdict: ? — test: — commit: — perf: —
- [ ] V-0054 CVE-2017-15398 (chromium (QUIC)) stack-buffer-overflow: Stack buffer overflow in the QUIC networking stack in Google Chrome prior to 62.0.3202.89 allowed a remote att
      ours: transport/* frame parser fixed-size stack buffers (varint/frame header decode) — verdict: ? — test: — commit: — perf: —
- [ ] V-0055 CVE-2019-5754 (chromium (QUIC)) crypto-downgrade: Implementation error in QUIC networking in Google Chrome allowed a man-in-the-middle attacker who controls a p
      ours: tls/* handshake completion checks before treating a connection as encrypted; proxy/CONNECT interaction with 0-RTT — verdict: ? — test: — commit: — perf: —
- [ ] V-0056 CVE-2024-3837 (chromium (QUIC)) use-after-free: Use-after-free in QUIC in Google Chrome allowed a remote attacker who had compromised the renderer process to 
      ours: transport/conn connection/stream close-and-free ordering vs. pending callbacks/timers — verdict: ? — test: — commit: — perf: —
- [ ] V-0057 CVE-2026-9114 (chromium (QUIC)) use-after-free: Use-after-free in QUIC enabled arbitrary code execution within the browser sandbox via malicious network traff
      ours: transport/conn stream/connection object lifetime across async callbacks (recv, timer, close) — verdict: ? — test: — commit: — perf: —
- [ ] V-0058 CVE-2026-13799 (chromium (QUIC)) use-after-free: Another use-after-free variant in Chrome's QUIC implementation, potentially allowing heap corruption exploitat
      ours: transport/conn same lifetime class as CVE-2026-9114, different trigger path — verdict: ? — test: — commit: — perf: —
- [ ] V-0059 CVE-2026-17673 (chromium (QUIC)) integer-overflow: Integer overflow in Chrome's QUIC implementation could facilitate a sandbox escape when the renderer process h
      ours: transport/* length/offset arithmetic on attacker-controlled varints (frame length, stream offset) — verdict: ? — test: — commit: — perf: —
- [ ] V-0060 CVE-2026-17733 (chromium (QUIC)) origin-policy-bypass: Inappropriate implementation in QUIC on Android permitted cross-origin data leakage via malicious web pages (o
      ours: app/http3 origin/authority validation against the negotiated connection identity — verdict: ? — test: — commit: — perf: —
- [ ] V-0061 CVE-2026-78893 (chromium (QUIC)) info-leak: Information disclosure in QUIC enabled attackers to extract sensitive data via specially designed HTML content
      ours: transport/* uninitialized/stale buffer reuse across connections or streams — verdict: ? — test: — commit: — perf: —
- [ ] V-0062 CVE-2026-78966 (chromium (QUIC)) origin-policy-bypass: Externally controlled reference in QUIC circumvented web origin policy protections through crafted web pages.
      ours: app/http3 or app/webtransport session/origin binding checks — verdict: ? — test: — commit: — perf: —
- [ ] V-0063 CVE-2026-40460 (nginx (ngx_http_v3_module)) source-address-spoofing: HTTP/3 address spoofing: an attacker could spoof the client address associated with an HTTP/3 (QUIC) connectio
      ours: transport/* path validation / connection-migration address binding used by the app layer for client identity — verdict: ? — test: — commit: — perf: —
- [ ] V-0064 CVE-2026-26080 (haproxy (QUIC)) loop-dos: Truncated varint loop: a QUIC packet containing a truncated variable-length integer causes HAProxy's frame par
      ours: transport/frame varint decode loop termination on truncated/malformed input — verdict: ? — test: — commit: — perf: —
- [ ] V-0065 CVE-2026-26081 (haproxy (QUIC)) integer-underflow: Token length underflow: a malformed QUIC Initial packet triggers an integer underflow during Retry/NEW_TOKEN t
      ours: transport/retry token length validation before subtraction/indexing — verdict: ? — test: — commit: — perf: —
- [ ] V-0066 CVE-2024-49214 (haproxy (QUIC)) source-address-spoofing: QUIC 0-RTT session establishment allowed a spoofed source IP address to bypass the configured IP allow/block l
      ours: transport/handshake 0-RTT acceptance path vs. address validation / anti-amplification gating — verdict: ? — test: — commit: — perf: —
- [ ] V-0067 CVE-2024-2379 (curl/libcurl (QUIC, wolfSSL backend)) cert-verification-bypass: QUIC certificate check bypass with wolfSSL: when curl (built against wolfSSL with OPENSSL_COMPATIBLE_DEFAULTS)
      ours: tls/* handshake error-path handling must not silently mark verification as passed on cipher/curve negotiation failure — verdict: ? — test: — commit: — perf: —
- [ ] V-0068 CVE-2025-5025 (curl/libcurl (QUIC, wolfSSL backend)) cert-pinning-bypass: No QUIC certificate pinning with wolfSSL: libcurl's public-key pinning (CURLOPT_PINNEDPUBLICKEY) was not enfor
      ours: tls/* public-key pin check must be wired into every TLS backend's QUIC handshake completion path, not only the default backend — verdict: ? — test: — commit: — perf: —
- [ ] V-0069 CVE-2025-4947 (curl/libcurl (QUIC, wolfSSL backend)) cert-verification-bypass: QUIC certificate check skip with wolfSSL: a related certificate-verification-skip defect in the wolfSSL QUIC b
      ours: tls/* handshake verification callback wiring, same class as CVE-2024-2379 — verdict: ? — test: — commit: — perf: —
- [ ] V-0070 CVE-2026-9545 (curl/libcurl (HTTP/3, ngtcp2+nghttp3 backend)) 0rtt-replay-exposure: Exposing HTTP/3 early data: the ngtcp2+nghttp3 backend could deliver request/response data sent as QUIC 0-RTT 
      ours: transport/handshake 0-RTT data must be tagged and surfaced to the app layer as replayable until the handshake completes — verdict: ? — test: — commit: — perf: —
- [ ] V-0071 CVE-2026-11352 (curl/libcurl (QUIC recv path, recvmmsg)) loop-dos: QUIC zero-length UDP datagrams busy-loop: a malicious HTTP/3 server could send zero-length UDP datagrams that 
      ours: transport/io UDP receive loop must treat a zero-length datagram as one consumed packet, not retry indefinitely — verdict: ? — test: — commit: — perf: —
- [ ] V-0072 CVE-2026-18798 (openssl (QUIC server, QRX)) use-after-free: Double-free of the QRX (QUIC record exchange) object when channel creation fails while processing an Initial p
      ours: transport/handshake Initial-packet channel creation failure path; ownership of the record-protection object must have exactly one owner on error — verdict: ? — test: — commit: — perf: —
- [ ] V-0073 CVE-2026-34183 (openssl (QUIC, path validation)) resource-exhaustion: PATH_CHALLENGE flood memory exhaustion: OpenSSL's QUIC stack allocates a PATH_RESPONSE frame for every PATH_CH
      ours: transport/path-validation PATH_RESPONSE queue must be bounded per connection independent of peer ACK behavior — verdict: ? — test: — commit: — perf: —
- [ ] V-0074 CVE-2026-54875 (openssl (QUIC, path validation)) resource-exhaustion: Recurrence of the PATH_CHALLENGE/PATH_RESPONSE unbounded-allocation issue (same class as CVE-2026-34183) reint
      ours: transport/path-validation same as CVE-2026-34183 — verify the fix bounds the queue rather than only rate-limiting — verdict: ? — test: — commit: — perf: —
- [ ] V-0075 CVE-2026-42764 (openssl (QUIC server, Initial packet)) null-deref: NULL pointer dereference when a QUIC Initial packet carries an invalid token while address validation is disab
      ours: transport/retry token validation failure path must not proceed to dereference the (absent) validated-token state — verdict: ? — test: — commit: — perf: —
- [ ] V-0076 CVE-2026-14456 (openssl (QUIC server, connection accept)) resource-exhaustion: Unbounded incoming-channel queue: a QUIC server processing valid Initial packets for unknown destination conne
      ours: transport/handshake pending-accept queue must be capped independent of application accept() rate — verdict: ? — test: — commit: — perf: —
- [ ] V-0077 CVE-2026-63075 (openssl (QUIC, ACK handling)) resource-exhaustion: ACK-only packet metadata retained for the lifetime of the connection when a peer repeatedly sends ack-elicitin
      ours: transport/recovery/ack sent-ACK-only-packet tracking must be bounded and reclaimed, not retained per-connection forever — verdict: ? — test: — commit: — perf: —
- [ ] V-0078 CVE-2025-23020 (kwik (QUIC, connection ID / hash table)) hash-dos: QUIC Hash-DoS: an attacker able to choose or influence connection IDs / packet fields fed into a hash table (e
      ours: transport/conn connection-ID-to-connection lookup table (or any peer-influenced-key hash table) must use a keyed/randomized hash, not a naive hash vulnerable to chosen-input collisions — verdict: ? — test: — commit: — perf: —
- [ ] V-0079 CVE-2023-44487 (HTTP/2 implementations generally (Rapid Reset); HTTP/3 stream-limit analogue is a design lesson, not a specific HTTP/3 CVE) stream-reset-flood: HTTP/2 Rapid Reset: a client repeatedly opens a new multiplexed stream and immediately cancels it with RST_STR
      ours: transport/streams stream creation+RESET_STREAM accounting must count client-initiated resets against a per-connection concurrent/rate limit, not just currently-open streams — the direct QUIC/HTTP-3 analogue of HTTP/2 Rapid Reset — verdict: ? — test: — commit: — perf: —
- [ ] V-0080 L-0001 (Hash Denial-of-Service Attack ) hash-dos: 
      ours: hash-dos — verdict: ? — test: — commit: — perf: —
- [ ] V-0081 L-0002 (Hash DoS affected implementati) hash-dos: 
      ours: hash-dos — verdict: ? — test: — commit: — perf: —
- [ ] V-0082 L-0003 (Hash DoS affected implementati) hash-dos: 
      ours: hash-dos — verdict: ? — test: — commit: — perf: —
- [ ] V-0083 L-0004 (Hash DoS affected implementati) hash-dos: 
      ours: hash-dos — verdict: ? — test: — commit: — perf: —
- [ ] V-0084 L-0005 (Hash DoS affected implementati) hash-dos: 
      ours: hash-dos — verdict: ? — test: — commit: — perf: —
- [ ] V-0085 L-0006 (Hash DoS affected implementati) hash-dos: 
      ours: hash-dos — verdict: ? — test: — commit: — perf: —
- [ ] V-0086 L-0007 (Hash DoS affected implementati) hash-dos: 
      ours: hash-dos — verdict: ? — test: — commit: — perf: —
- [ ] V-0087 L-0008 (Hash DoS affected implementati) hash-dos: 
      ours: hash-dos — verdict: ? — test: — commit: — perf: —
- [ ] V-0088 L-0009 (Hash DoS affected implementati) hash-dos: 
      ours: hash-dos — verdict: ? — test: — commit: — perf: —
- [ ] V-0089 L-0010 (Hash DoS affected implementati) hash-dos: 
      ours: hash-dos — verdict: ? — test: — commit: — perf: —
- [ ] V-0090 L-0011 (Revisiting QUIC attacks (IJIS ) zero-rtt-replay: 
      ours: zero-rtt-replay — verdict: ? — test: — commit: — perf: —
- [ ] V-0091 L-0012 (Revisiting QUIC attacks (IJIS ) migration-hijack: 
      ours: migration-hijack — verdict: ? — test: — commit: — perf: —
- [ ] V-0092 L-0013 (Revisiting QUIC attacks (IJIS ) version-downgrade: 
      ours: version-downgrade — verdict: ? — test: — commit: — perf: —
- [ ] V-0093 L-0014 (Revisiting QUIC attacks (IJIS ) amplification: 
      ours: amplification — verdict: ? — test: — commit: — perf: —
- [ ] V-0094 L-0015 (Revisiting QUIC attacks (IJIS ) header-malformed-input: 
      ours: header-malformed-input — verdict: ? — test: — commit: — perf: —
- [ ] V-0095 L-0016 (Revisiting QUIC attacks (IJIS ) handshake-flood: 
      ours: handshake-flood — verdict: ? — test: — commit: — perf: —
- [ ] V-0096 L-0017 (Revisiting QUIC attacks (IJIS ) traffic-fingerprinting: 
      ours: traffic-fingerprinting — verdict: ? — test: — commit: — perf: —
- [ ] V-0097 L-0018 (Revisiting QUIC attacks (IJIS ) parser-fuzz-crash: 
      ours: parser-fuzz-crash — verdict: ? — test: — commit: — perf: —
- [ ] V-0098 L-0019 (Optimistic ACK attack on QUIC ) optimistic-ack: 
      ours: optimistic-ack — verdict: ? — test: — commit: — perf: —
- [ ] V-0099 L-0020 (QUIC-LEAK: pre-handshake memor) pre-handshake-memory-exhaustion: 
      ours: pre-handshake-memory-exhaustion — verdict: ? — test: — commit: — perf: —
- [ ] V-0100 L-0022 (Loop DoS: self-perpetuating UD) loop-dos: 
      ours: loop-dos — verdict: ? — test: — commit: — perf: —
- [ ] V-0101 L-0023 (QUIC amplification/reflection:) amplification: 
      ours: amplification — verdict: ? — test: — commit: — perf: —
- [ ] V-0102 L-0024 (QUIC version-negotiation downg) version-downgrade: 
      ours: version-downgrade — verdict: ? — test: — commit: — perf: —
- [ ] V-0103 L-0025 (Does It Spin? On the Adoption ) spin-bit-linkability: 
      ours: spin-bit-linkability — verdict: ? — test: — commit: — perf: —
- [ ] V-0104 S-8999-7-1 (RFC 8999) Version-based traffic fingerprinting by middleboxes: QUIC version 1 makes some effort to eliminate or obscure observable traits, but implemente
      ours: ossification — verdict: ? — test: — commit: — perf: —
- [ ] V-0105 S-8999-7-2 (RFC 8999) Connection-ID-keyed state required for version fingerprinting: Implicitly discourages relying on per-packet version visibility; endpoints should not assu
      ours: traffic-analysis — verdict: ? — test: — commit: — perf: —
- [ ] V-0106 S-8999-7-3 (RFC 8999) Unauthenticated Version Negotiation packet spoofing / forced downgrade: An endpoint MUST authenticate the semantic content of a Version Negotiation packet before 
      ours: version-downgrade — verdict: ? — test: — commit: — perf: —
- [ ] V-0107 S-9287-4-1 (RFC 9287) Loss of QUIC Bit as a network classification signal: The mechanism introduces no new security considerations for cooperating endpoints; operato
      ours: greasing-detection — verdict: ? — test: — commit: — perf: —
- [ ] V-0108 S-9000-21.1-1 (RFC 9000) Security analysis scope and threat model: Section provides informal security-property description per RFC 3552 threat model; not a c
      ours: threat-model-scope — verdict: ? — test: — commit: — perf: —
- [ ] V-0109 S-9000-21.1-2 (RFC 9000) Passive vs active attacker classification: None (definitional); frames subsequent attack analysis around this split.
      ours: traffic-analysis — verdict: ? — test: — commit: — perf: —
- [ ] V-0110 S-9000-21.1-3 (RFC 9000) On-path vs off-path attacker classification: None (definitional); used to scope which mitigations apply to which attacker class.
      ours: path-validation — verdict: ? — test: — commit: — perf: —
- [ ] V-0111 S-9000-21.1-4 (RFC 9000) Handshake/protected-packets/migration considered separately: Properties of the handshake, protected packets, and connection migration are analyzed sepa
      ours: threat-model-scope — verdict: ? — test: — commit: — perf: —
- [ ] V-0112 S-9000-21.1.1-1 (RFC 9000) TLS handshake compromise propagates to QUIC: QUIC's security properties for the handshake depend on TLS 1.3 handshake properties being 
      ours: handshake-compromise — verdict: ? — test: — commit: — perf: —
- [ ] V-0113 S-9000-21.1.1-2 (RFC 9000) Migration linkability depends on handshake key secrecy: Migration (Section 9) depends on the efficacy of confidentiality protections both for TLS 
      ours: migration-linkability — verdict: ? — test: — commit: — perf: —
- [ ] V-0114 S-9000-21.1.1-3 (RFC 9000) Handshake integrity attack can force protocol/version downgrade: None stated beyond noting the risk; relies on TLS handshake integrity.
      ours: version-downgrade — verdict: ? — test: — commit: — perf: —
- [ ] V-0115 S-9000-21.1.1-4 (RFC 9000) QUIC handshake adds DoS defenses beyond TLS: In addition to TLS-provided properties, the QUIC handshake provides some defense against D
      ours: dos-computation — verdict: ? — test: — commit: — perf: —
- [ ] V-0116 S-9000-21.1.1.1-1 (RFC 9000) Amplification attack via unvalidated address: Address validation (Section 8) verifies an entity claiming an address can receive packets 
      ours: amplification — verdict: ? — test: — commit: — perf: —
- [ ] V-0117 S-9000-21.1.1.1-2 (RFC 9000) Anti-amplification 3x send limit: Endpoints cannot send data toward an unvalidated address in excess of three times the data
      ours: amplification — verdict: ? — test: — commit: — perf: —
- [ ] V-0118 S-9000-21.1.1.1-3 (RFC 9000) Anti-amplification limit scope note: Note: the anti-amplification limit only applies when an endpoint responds to packets from 
      ours: amplification — verdict: ? — test: — commit: — perf: —
- [ ] V-0119 S-9000-21.1.1.2-1 (RFC 9000) Computational DoS via expensive handshake first flight: The Retry packet provides a cheap token exchange mechanism letting servers validate a clie
      ours: dos-computation — verdict: ? — test: — commit: — perf: —
- [ ] V-0120 S-9000-21.1.1.3-1 (RFC 9000) On-path/off-path forced handshake failure via Initial packet racing: Handshake packets after Initial are protected with Handshake keys, limiting on-path attack
      ours: handshake-compromise — verdict: ? — test: — commit: — perf: —
- [ ] V-0121 S-9000-21.1.1.3-2 (RFC 9000) On-path address rewriting looks like NAT: This attack is indistinguishable from ordinary NAT behavior; no specific defense given bey
      ours: migration-linkability — verdict: ? — test: — commit: — perf: —
- [ ] V-0122 S-9000-21.1.1.4-1 (RFC 9000) Transport parameter negotiation integrity/confidentiality: The entire handshake including parameter negotiation is cryptographically protected via th
      ours: handshake-compromise — verdict: ? — test: — commit: — perf: —
- [ ] V-0123 S-9000-21.1.1.4-2 (RFC 9000) No version negotiation security mechanism in this version: This version of QUIC does not incorporate a version negotiation mechanism.
      ours: version-downgrade — verdict: ? — test: — commit: — perf: —
- [ ] V-0124 S-9000-21.1.2-1 (RFC 9000) Scope: packet protection covers all but Version Negotiation: Packet protection (Section 12.1) applies authenticated encryption to all packets except Ve
      ours: handshake-compromise — verdict: ? — test: — commit: — perf: —
- [ ] V-0125 S-9000-21.1.2-2 (RFC 9000) Passive record-and-crack (harvest-now) attack: None stated as a mitigation in this paragraph beyond noting this applies to any observer o
      ours: traffic-analysis — verdict: ? — test: — commit: — perf: —
- [ ] V-0126 S-9000-21.1.2-3 (RFC 9000) Blind packet injection is unlikely to succeed: Packet protection ensures valid packets are only generated by endpoints possessing the key
      ours: handshake-compromise — verdict: ? — test: — commit: — perf: —
- [ ] V-0127 S-9000-21.1.2-4 (RFC 9000) Spoofing attack requires forwarding ability: Packet protection ensures payloads are only processed by endpoints that completed the hand
      ours: path-validation — verdict: ? — test: — commit: — perf: —
- [ ] V-0128 S-9000-21.1.2-5 (RFC 9000) Datagram/packet coalescing boundary manipulation: Aside from datagrams containing Initial packets (which require padding), this has no funct
      ours: amplification — verdict: ? — test: — commit: — perf: —
- [ ] V-0129 S-9000-21.1.3-1 (RFC 9000) Connection migration and path validation overview: Path validation (Section 8.2) establishes that a peer is both willing and able to receive 
      ours: migration-linkability — verdict: ? — test: — commit: — perf: —
- [ ] V-0130 S-9000-21.1.3-2 (RFC 9000) Migration security properties under DoS to be detailed: This section describes the intended security properties of connection migration under vari
      ours: migration-linkability — verdict: ? — test: — commit: — perf: —
- [ ] V-0131 S-9000-21.1.3.1-1 (RFC 9000) On-path attacker definition for migration analysis: None (definitional).
      ours: path-validation — verdict: ? — test: — commit: — perf: —
- [ ] V-0132 S-9000-21.1.3.1-2 (RFC 9000) On-path attacker capability list: None (threat enumeration) — bounds what protections must resist.
      ours: path-validation — verdict: ? — test: — commit: — perf: —
- [ ] V-0133 S-9000-21.1.3.1-3 (RFC 9000) On-path attacker cannot forge authenticated content: Packet payloads are authenticated and encrypted, so any modification to the authenticated 
      ours: path-validation — verdict: ? — test: — commit: — perf: —
- [ ] V-0134 S-9000-21.1.3.1-4 (RFC 9000) On-path attacker can force connection failure by blocking the path: None beyond noting this is a fundamental limit of the threat model; QUIC aims to constrain
      ours: path-validation — verdict: ? — test: — commit: — perf: —
- [ ] V-0135 S-9000-21.1.3.1-5 (RFC 9000) On-path attacker can block migration to a path it is also on: Implicit: migrating to a path where the attacker is NOT on-path defeats this attacker.
      ours: migration-linkability — verdict: ? — test: — commit: — perf: —
- [ ] V-0136 S-9000-21.1.3.1-6 (RFC 9000) On-path attacker cannot block migration to attacker-free path: An on-path attacker cannot prevent a client from migrating to a path for which the attacke
      ours: migration-linkability — verdict: ? — test: — commit: — perf: —
- [ ] V-0137 S-9000-21.1.3.1-7 (RFC 9000) On-path attacker can degrade throughput: None stated as a full defense; inherent to on-path position.
      ours: peer-dos — verdict: ? — test: — commit: — perf: —
- [ ] V-0138 S-9000-21.1.3.1-8 (RFC 9000) On-path attacker cannot forge accepted modified packets (restated): An on-path attacker cannot cause an endpoint to accept a packet for which it has modified 
      ours: path-validation — verdict: ? — test: — commit: — perf: —
- [ ] V-0139 S-9000-21.1.3.2-1 (RFC 9000) Off-path attacker definition: None (definitional).
      ours: path-validation — verdict: ? — test: — commit: — perf: —
- [ ] V-0140 S-9000-21.1.3.2-2 (RFC 9000) Off-path attacker capability list: None (threat enumeration).
      ours: path-validation — verdict: ? — test: — commit: — perf: —
- [ ] V-0141 S-9000-21.1.3.2-3 (RFC 9000) Off-path attacker can race injected copies to win against originals: None stated in this paragraph beyond describing the assumed capability for subsequent anal
      ours: path-validation — verdict: ? — test: — commit: — perf: —
- [ ] V-0142 S-9000-21.1.3.2-4 (RFC 9000) Attacker assumed able to win packet races: None (worst-case assumption for analysis).
      ours: path-validation — verdict: ? — test: — commit: — perf: —
- [ ] V-0143 S-9000-21.1.3.2-5 (RFC 9000) Attacker can disrupt NAT bindings: None stated as mitigation in this paragraph; assumed capability.
      ours: migration-linkability — verdict: ? — test: — commit: — perf: —
- [ ] V-0144 S-9000-21.1.3.2-6 (RFC 9000) Off-path attacker can become a limited on-path attacker by racing: None (capability statement); addressed via the limited-on-path-attacker constraints in 21.
      ours: path-validation — verdict: ? — test: — commit: — perf: —
- [ ] V-0145 S-9000-21.1.3.2-7 (RFC 9000) Off-path attacker can pass path validation by improving connectivity: None stated beyond the constraint boundary (this is an accepted limitation of path validat
      ours: path-validation — verdict: ? — test: — commit: — perf: —
- [ ] V-0146 S-9000-21.1.3.2-8 (RFC 9000) Off-path attacker cannot close an established connection: An off-path attacker cannot cause a connection to close once the handshake has completed.
      ours: peer-dos — verdict: ? — test: — commit: — perf: —
- [ ] V-0147 S-9000-21.1.3.2-9 (RFC 9000) Off-path attacker cannot fail migration to a path it cannot observe: An off-path attacker cannot cause migration to a new path to fail if it cannot observe the
      ours: migration-linkability — verdict: ? — test: — commit: — perf: —
- [ ] V-0148 S-9000-21.1.3.2-10 (RFC 9000) Off-path attacker can become limited on-path during migration to a path it observes: None stated as full mitigation; bounds the attacker's power during migration.
      ours: migration-linkability — verdict: ? — test: — commit: — perf: —
- [ ] V-0149 S-9000-21.1.3.2-11 (RFC 9000) Off-path attacker can become limited on-path via shared NAT state manipulation: None stated as full mitigation in this paragraph.
      ours: migration-linkability — verdict: ? — test: — commit: — perf: —
- [ ] V-0150 S-9000-21.1.3.3-1 (RFC 9000) Limited on-path attacker definition: None (definitional).
      ours: path-validation — verdict: ? — test: — commit: — perf: —
- [ ] V-0151 S-9000-21.1.3.3-2 (RFC 9000) Limited on-path attacker does not block the original path: A future failure to route copied packets faster than the original path will not prevent or
      ours: path-validation — verdict: ? — test: — commit: — perf: —
- [ ] V-0152 S-9000-21.1.3.3-3 (RFC 9000) Limited on-path attacker capability list: None (threat enumeration).
      ours: path-validation — verdict: ? — test: — commit: — perf: —
- [ ] V-0153 S-9000-21.1.3.3-4 (RFC 9000) Limited on-path attacker cannot delay beyond original arrival, drop, or forge authenticated content: Structural limitation of this attacker class relative to a full on-path attacker.
      ours: path-validation — verdict: ? — test: — commit: — perf: —
- [ ] V-0154 S-9000-21.1.3.3-5 (RFC 9000) Limited on-path attacker cannot offer worse latency or truly drop packets: Inherent structural limitation, not an active defense mechanism.
      ours: path-validation — verdict: ? — test: — commit: — perf: —
- [ ] V-0155 S-9000-21.1.3.3-6 (RFC 9000) Limited on-path attacker cannot close an established connection: A limited on-path attacker cannot cause a connection to close once the handshake has compl
      ours: peer-dos — verdict: ? — test: — commit: — perf: —
- [ ] V-0156 S-9000-21.1.3.3-7 (RFC 9000) Limited on-path attacker cannot close idle connection if client resumes first: A limited on-path attacker cannot cause an idle connection to close if the client is first
      ours: idle-connections — verdict: ? — test: — commit: — perf: —
- [ ] V-0157 S-9000-21.1.3.3-8 (RFC 9000) Limited on-path attacker CAN cause idle connection loss if server resumes first: Note: these guarantees are the same as those provided for any NAT, for the same reasons.
      ours: idle-connections — verdict: ? — test: — commit: — perf: —
- [ ] V-0158 S-9000-21.2-1 (RFC 9000) Post-handshake protections against DoS: As an encrypted/authenticated transport, once the handshake completes QUIC endpoints disca
      ours: dos-computation — verdict: ? — test: — commit: — perf: —
- [ ] V-0159 S-9000-21.2-2 (RFC 9000) Limited unauthenticated packet acceptance post-handshake: Endpoints might accept some unauthenticated ICMP packets (Section 14.2.1) in extremely lim
      ours: stateless-reset-guessing — verdict: ? — test: — commit: — perf: —
- [ ] V-0160 S-9000-21.2-3 (RFC 9000) Handshake-time protection is only against off-path attackers: All QUIC packets contain proof that the recipient saw a preceding packet from its peer.
      ours: handshake-compromise — verdict: ? — test: — commit: — perf: —
- [ ] V-0161 S-9000-21.2-4 (RFC 9000) Address cannot change during handshake: Addresses cannot change during the handshake, so endpoints can discard packets received on
      ours: path-validation — verdict: ? — test: — commit: — perf: —
- [ ] V-0162 S-9000-21.2-5 (RFC 9000) Connection ID matching as off-path handshake protection: The Source/Destination Connection ID fields (Section 8.1) are required to match those set 
      ours: address-validation — verdict: ? — test: — commit: — perf: —
- [ ] V-0163 S-9000-21.2-6 (RFC 9000) Unpredictable client-chosen Initial DCID doubles as key derivation input: The Initial packet's Destination Connection ID is chosen by the client to be unpredictable
      ours: address-validation — verdict: ? — test: — commit: — perf: —
- [ ] V-0164 S-9000-21.2-7 (RFC 9000) Protections do not stop an on-path/pre-connection attacker: This version of QUIC attempts to detect this sort of attack but expects endpoints will fai
      ours: handshake-compromise — verdict: ? — test: — commit: — perf: —
- [ ] V-0165 S-9000-21.2-8 (RFC 9000) Endpoints may use additional detection methods: Endpoints are permitted to use other methods to detect and recover from handshake interfer
      ours: handshake-compromise — verdict: ? — test: — commit: — perf: —
- [ ] V-0166 S-9000-21.3-1 (RFC 9000) Amplification via released/reused address validation token: Servers SHOULD provide mitigations by limiting the usage and lifetime of address validatio
      ours: amplification — verdict: ? — test: — commit: — perf: —
- [ ] V-0167 S-9000-21.4-1 (RFC 9000) Optimistic ACK attack to inflate congestion window: An endpoint MAY skip packet numbers when sending to detect this behavior, and can then imm
      ours: dos-computation — verdict: ? — test: — commit: — perf: —
- [ ] V-0168 S-9000-21.5-1 (RFC 9000) Request forgery attack definition: None yet (definitional); mitigations follow in 21.5.1-21.5.6.
      ours: request-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0169 S-9000-21.5-2 (RFC 9000) Requirement for request forgery to be effective: None (definitional/precondition).
      ours: request-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0170 S-9000-21.5-3 (RFC 9000) CSRF analogy: None (analogy, informative).
      ours: request-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0171 S-9000-21.5-4 (RFC 9000) QUIC/UDP request forgery attack modality: None yet; scope-setting for the section's later mitigations.
      ours: request-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0172 S-9000-21.5-5 (RFC 9000) Section scope and limits of countermeasures: This section describes ways QUIC might be used for request forgery and describes limited c
      ours: request-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0173 S-9000-21.5-6 (RFC 9000) Servers should assume attackers can force arbitrary UDP payloads to arbitrary destinations: QUIC servers SHOULD NOT be deployed in networks that lack ingress filtering (BCP 38) and a
      ours: request-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0174 S-9000-21.5-7 (RFC 9000) Servers cannot migrate in this version, limiting spoofed-migration attacks on clients: This version of QUIC does not allow servers to migrate, preventing spoofed migration attac
      ours: request-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0175 S-9000-21.5.1-1 (RFC 9000) Enumeration of peer-influence vectors: None yet (enumeration); in all cases these packets are sent prior to address validation (S
      ours: request-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0176 S-9000-21.5.1-2 (RFC 9000) Direct content-control fields: DCID and Token: None (describes attacker capability, not yet mitigated).
      ours: request-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0177 S-9000-21.5.1-3 (RFC 9000) No measures against indirect control of encrypted content: There are no measures in this version of QUIC to prevent this indirect control over encryp
      ours: request-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0178 S-9000-21.5.1-4 (RFC 9000) Mitigation focus is on pre-validation datagrams: This section assumes limiting control over datagram content is not feasible; subsequent mi
      ours: request-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0179 S-9000-21.5.2-1 (RFC 9000) Server-as-attacker can choose its own advertised address: Address validation implicit in the handshake limits exposure to Initial packets only.
      ours: request-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0180 S-9000-21.5.2-2 (RFC 9000) Initial packet protection limits server control of Initial content: Initial packet protection makes it difficult for servers to control Initial packet content
      ours: request-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0181 S-9000-21.5.2-3 (RFC 9000) Token field is server-controlled and forgeable via NEW_TOKEN: Clients are not obligated to use NEW_TOKEN; sending an empty Token field when the server a
      ours: request-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0182 S-9000-21.5.2-4 (RFC 9000) Trade-off of avoiding NEW_TOKEN on address change: Not including a Token field could adversely affect performance since servers rely on NEW_T
      ours: amplification — verdict: ? — test: — commit: — perf: —
- [ ] V-0183 S-9000-21.5.2-5 (RFC 9000) Retry packet lets server change Token/DCID but validates its own address: However, the Retry exchange validates the server's address, preventing use of subsequent I
      ours: request-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0184 S-9000-21.5.3-1 (RFC 9000) Preferred address DCID usable for request forgery: None yet.
      ours: request-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0185 S-9000-21.5.3-2 (RFC 9000) Clients must not send non-probing frames before validating preferred address: A client MUST NOT send non-probing frames to a preferred address prior to validating that 
      ours: request-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0186 S-9000-21.5.3-3 (RFC 9000) No preferred-address-specific countermeasures beyond generic ones: This document offers no additional preferred-address-specific countermeasures; the generic
      ours: request-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0187 S-9000-21.5.4-1 (RFC 9000) Client can spoof source address to redirect server datagrams: None yet in this paragraph.
      ours: request-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0188 S-9000-21.5.4-2 (RFC 9000) Probing-only restriction limits but doesn't eliminate control: A server that only sends probing packets (Section 9.1) to an address prior to validation p
      ours: request-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0189 S-9000-21.5.4-3 (RFC 9000) No endpoint-specific countermeasure; network-level ingress filtering recommended: This document offers no specific endpoint countermeasures beyond the generic measures in S
      ours: request-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0190 S-9000-21.5.5-1 (RFC 9000) Spoofed source triggers server Version Negotiation packet toward victim: None yet in this paragraph.
      ours: version-downgrade — verdict: ? — test: — commit: — perf: —
- [ ] V-0191 S-9000-21.5.5-2 (RFC 9000) Large attacker-controlled payload in Version Negotiation response: No specific countermeasures are provided for this attack, though generic protections (Sect
      ours: version-downgrade — verdict: ? — test: — commit: — perf: —
- [ ] V-0192 S-9000-21.5.6-1 (RFC 9000) Strong authentication is the most effective defense: The most effective defense against request forgery is modifying vulnerable services to use
      ours: request-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0193 S-9000-21.5.6-2 (RFC 9000) Loopback address protection is discretionary: Endpoints SHOULD NOT prevent (i.e., MAY allow) connection attempts or migration to a loopb
      ours: request-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0194 S-9000-21.5.6-3 (RFC 9000) Link-local/private-range address change as forgery signal: Endpoints could refuse to use these addresses, but that risks interfering with legitimate 
      ours: request-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0195 S-9000-21.5.6-4 (RFC 9000) Restricting NEW_TOKEN reuse and non-probing frames pre-validation: Endpoints MAY choose to reduce request forgery risk by not including NEW_TOKEN values in I
      ours: request-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0196 S-9000-21.5.6-5 (RFC 9000) Avoiding known-bad target ports/patterns: Endpoints are not expected to have specific information about vulnerable server locations,
      ours: request-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0197 S-9000-21.5.6-6 (RFC 9000) Endpoint-side mitigation is more efficient than network-based: Note: modifying endpoints to apply these protections is more efficient than deploying netw
      ours: request-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0198 S-9000-21.6-1 (RFC 9000) Slowloris-style connection-holding attack: QUIC deployments SHOULD provide mitigations such as increasing the maximum number of allow
      ours: slowloris — verdict: ? — test: — commit: — perf: —
- [ ] V-0199 S-9000-21.7-1 (RFC 9000) Adversarial sender withholds stream data to bloat receiver buffers: None yet in this paragraph.
      ours: stream-fragmentation — verdict: ? — test: — commit: — perf: —
- [ ] V-0200 S-9000-21.7-2 (RFC 9000) Adversarial receiver withholds ACKs to force sender retransmission buffering: None yet in this paragraph.
      ours: stream-fragmentation — verdict: ? — test: — commit: — perf: —
- [ ] V-0201 S-9000-21.7-3 (RFC 9000) Flow control windows mitigate the sender-side attack, with a caveat: The attack on receivers is mitigated if flow control windows correspond to available memor
      ours: stream-fragmentation — verdict: ? — test: — commit: — perf: —
- [ ] V-0202 S-9000-21.7-4 (RFC 9000) Recommended mitigations for stream fragmentation attacks: QUIC deployments SHOULD provide mitigations such as avoiding memory overcommitment, limiti
      ours: stream-fragmentation — verdict: ? — test: — commit: — perf: —
- [ ] V-0203 S-9000-21.8-1 (RFC 9000) Stream commitment / SYN-flood analog via many streams: None yet in this paragraph.
      ours: stream-limit — verdict: ? — test: — commit: — perf: —
- [ ] V-0204 S-9000-21.8-2 (RFC 9000) Out-of-order stream opening amplifies stream count: None yet in this paragraph (this is the mechanism, not the fix).
      ours: stream-limit — verdict: ? — test: — commit: — perf: —
- [ ] V-0205 S-9000-21.8-3 (RFC 9000) MAX_STREAMS-based limits mitigate stream commitment attack: The number of active streams is limited by initial_max_streams_bidi/uni transport paramete
      ours: stream-limit — verdict: ? — test: — commit: — perf: —
- [ ] V-0206 S-9000-21.9-1 (RFC 9000) Legitimate-but-abusable frames/messages exhaust peer processing: None yet in this paragraph.
      ours: peer-dos — verdict: ? — test: — commit: — perf: —
- [ ] V-0207 S-9000-21.9-2 (RFC 9000) State can be churned in small, inconsequential increments: None yet in this paragraph.
      ours: peer-dos — verdict: ? — test: — commit: — perf: —
- [ ] V-0208 S-9000-21.9-3 (RFC 9000) Disproportionate processing cost relative to bandwidth/effect: None yet in this paragraph.
      ours: peer-dos — verdict: ? — test: — commit: — perf: —
- [ ] V-0209 S-9000-21.9-4 (RFC 9000) Recommended cost-tracking and response: Implementations SHOULD track the cost of processing relative to progress and treat excessi
      ours: peer-dos — verdict: ? — test: — commit: — perf: —
- [ ] V-0210 S-9000-21.10-1 (RFC 9000) On-path ECN field manipulation to influence sender rate: Referred elsewhere (Section 13.4 / ECN discussion) for detailed manipulation effects.
      ours: ecn-manipulation — verdict: ? — test: — commit: — perf: —
- [ ] V-0211 S-9000-21.10-2 (RFC 9000) Limited on-path duplicate-and-modify-ECN attack: QUIC endpoints ignore the ECN field in an IP packet unless at least one QUIC packet in tha
      ours: ecn-manipulation — verdict: ? — test: — commit: — perf: —
- [ ] V-0212 S-9000-21.11-1 (RFC 9000) Stateless reset as TCP-reset-injection analog: None yet in this paragraph (describes the attack).
      ours: stateless-reset-guessing — verdict: ? — test: — commit: — perf: —
- [ ] V-0213 S-9000-21.11-2 (RFC 9000) Cross-instance routing enables a stateless-reset oracle: Endpoints that share a static key for stateless resets (Section 10.3.2) MUST be arranged s
      ours: stateless-reset-guessing — verdict: ? — test: — commit: — perf: —
- [ ] V-0214 S-9000-21.11-3 (RFC 9000) Servers must not generate stateless reset if connection could still be active elsewhere: Servers MUST NOT generate a stateless reset if a connection with the corresponding connect
      ours: stateless-reset-guessing — verdict: ? — test: — commit: — perf: —
- [ ] V-0215 S-9000-21.11-4 (RFC 9000) Dynamic load-balancer reconfiguration edge case: In a dynamically load-balanced cluster, a load-balancer reconfiguration could route packet
      ours: stateless-reset-guessing — verdict: ? — test: — commit: — perf: —
- [ ] V-0216 S-9000-21.12-1 (RFC 9000) No downgrade-attack protection in Version Negotiation packets: Future versions of QUIC that use Version Negotiation packets MUST define a mechanism that 
      ours: version-downgrade — verdict: ? — test: — commit: — perf: —
- [ ] V-0217 S-9000-21.13-1 (RFC 9000) Attacker targeting a specific server instance via routing: Deployments should limit the ability of an attacker to target a new connection to a partic
      ours: dos-computation — verdict: ? — test: — commit: — perf: —
- [ ] V-0218 S-9000-21.14-1 (RFC 9000) Packet length reveals content length information: The PADDING frame (Section 19.1) gives endpoints some ability to obscure the length of pac
      ours: traffic-analysis — verdict: ? — test: — commit: — perf: —
- [ ] V-0219 S-9000-21.14-2 (RFC 9000) Traffic analysis beyond length is an open problem: Defeating traffic analysis is challenging and the subject of active research; no specific 
      ours: traffic-analysis — verdict: ? — test: — commit: — perf: —
- [ ] V-0220 S-9002-8.1-1 (RFC 9002) Manipulation of unauthenticated loss/congestion signals: Implicit: implementations should treat these signals as attacker-influenceable and design 
      ours: ecn-manipulation — verdict: ? — test: — commit: — perf: —
- [ ] V-0221 S-9002-8.2-1 (RFC 9002) Traffic analysis via ACK-only packet size/pattern: To reduce leaked information, endpoints can bundle acknowledgments with other frames or us
      ours: traffic-analysis — verdict: ? — test: — commit: — perf: —
- [ ] V-0222 S-9002-8.3-1 (RFC 9002) ECN-CE misreporting to induce sender rate increase: Implicit: senders should be able to detect and react to suppressed ECN-CE reporting (see n
      ours: ecn-manipulation — verdict: ? — test: — commit: — perf: —
- [ ] V-0223 S-9002-8.3-2 (RFC 9002) Detecting ECN-CE suppression via self-marked probe packets: A sender can detect suppression of reports by marking occasional packets it sends with an 
      ours: ecn-manipulation — verdict: ? — test: — commit: — perf: —
- [ ] V-0224 S-9002-8.3-3 (RFC 9002) Over-reporting ECN-CE gives the attacker no advantage: Reporting additional ECN-CE markings causes a sender to reduce its sending rate, which is 
      ours: ecn-manipulation — verdict: ? — test: — commit: — perf: —
- [ ] V-0225 S-9002-8.3-4 (RFC 9002) Congestion controller response to ECN-CE varies by implementation: Endpoints choose the congestion controller they use; congestion controllers respond to rep
      ours: ecn-manipulation — verdict: ? — test: — commit: — perf: —
- [ ] V-0226 S-9368-9-1 (RFC 9368) Compatible version negotiation security is bounded by the weakest common version: Negotiation between compatible versions will have the security of the weakest common versi
      ours: version-downgrade — verdict: ? — test: — commit: — perf: —
- [ ] V-0227 S-9368-9-2 (RFC 9368) Undocumented compatibility could enable cross-version attacks: Versions MUST NOT be treated as compatible unless that compatibility is explicitly documen
      ours: version-downgrade — verdict: ? — test: — commit: — perf: —
- [ ] V-0228 S-9369-8-1 (RFC 9369) QUIC v2 preserves v1 security/privacy properties: QUIC version 2 introduces no changes to the security or privacy properties of QUIC version
      ours: version-downgrade — verdict: ? — test: — commit: — perf: —
- [ ] V-0229 S-9369-8-2 (RFC 9369) Mandatory version negotiation guards against downgrade, but downgrade is not itself harmful between v1/v2: The mandatory version negotiation mechanism guards against downgrade attacks; however, a d
      ours: version-downgrade — verdict: ? — test: — commit: — perf: —
- [ ] V-0230 S-9369-8-3 (RFC 9369) Version support as a fingerprinting signal: Acknowledged as a privacy consideration with no specific mitigation prescribed beyond noti
      ours: traffic-analysis — verdict: ? — test: — commit: — perf: —
- [ ] V-0231 S-ackfreq-10-1 (draft-ietf-quic-ack-frequency-14) DoS via excessive requested ACK frequency: This is mitigated because acknowledgment rates are inherently constrained by incoming data
      ours: ack-frequency-abuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0232 S-ackfreq-10-2 (draft-ietf-quic-ack-frequency-14) Control-frame processing cost DoS via ACK_FREQUENCY / IMMEDIATE_ACK: Implementations should apply the same peer-DoS mitigations described in RFC 9000 Section 2
      ours: dos-computation — verdict: ? — test: — commit: — perf: —
- [ ] V-0233 S-ackfreq-10-3 (draft-ietf-quic-ack-frequency-14) IMMEDIATE_ACK amplifies both reception and transmission cost: Implicit: implementations should rate-limit or bound how often they honor IMMEDIATE_ACK re
      ours: ack-frequency-abuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0234 S-ackfreq-10-4 (draft-ietf-quic-ack-frequency-14) Receiver retains final control over ACK frequency: With this extension, a sender cannot force a receiver to acknowledge more frequently than 
      ours: ack-frequency-abuse — verdict: ? — test: — commit: — perf: —

## TLS 1.3 (RFC 8446 and key exchange RFCs)

- [ ] V-0235 CVE-2025-13034 (curl (ngtcp2/GnuTLS backend)) cert-validation-bypass: curl's public-key pinning check for the server certificate was skipped when using QUIC with the ngtcp2/GnuTLS 
      ours: TLS backend certificate-pin verification hook wiring for the QUIC/ngtcp2 TLS integration path — verdict: ? — test: — commit: — perf: —
- [ ] V-0236 GHSA-w5f4-fx9m-m4q7 (msquic) cert-validation-bypass: Improper TLS hostname verification allows a man-in-the-middle attack on MsQuic when built against the OpenSSL/
      ours: hostname verification wiring for the OpenSSL/QuicTLS TLS backend adapter (RFC 6125/9525 name matching not invoked or bypassed) — verdict: ? — test: — commit: — perf: —
- [ ] V-0237 CVE-2026-6328 (xquic) cert-validation-bypass: Improper input validation and improper verification of cryptographic signature in XQUIC on Linux, enabling pro
      ours: signature verification step in the TLS/handshake integration (verify-result not enforced before proceeding) — verdict: ? — test: — commit: — perf: —
- [ ] V-0238 CVE-2026-5503 (wolfssl) extension-parsing: ECH extension pollution causes buffer overflow in ClientHello.
      ours: src/tls (extension parsing, ClientHello) — verdict: ? — test: — commit: — perf: —
- [ ] V-0239 CVE-2026-3547 (wolfssl) extension-parsing: Out-of-bounds read in ALPN parsing.
      ours: src/tls (ALPN extension parsing) — verdict: ? — test: — commit: — perf: —
- [ ] V-0240 CVE-2026-3549 (wolfssl) extension-parsing: Heap overflow in TLS 1.3 ECH parsing via integer underflow.
      ours: src/tls (ECH/extension parsing) — verdict: ? — test: — commit: — perf: —
- [ ] V-0241 CVE-2026-55962 (wolfssl) key-schedule: TLS 1.3 post-handshake auth accepts Finished without Certificate.
      ours: src/tls (post-handshake auth state machine) — verdict: ? — test: — commit: — perf: —
- [ ] V-0242 CVE-2026-11703 (wolfssl) key-schedule: Missing SNI/ALPN binding on stateful session resumption.
      ours: src/tls (session resumption / PSK binding) — verdict: ? — test: — commit: — perf: —
- [ ] V-0243 CVE-2026-3230 (wolfssl) key-schedule: TLS 1.3 client misses key_share absence in ServerHello (no HRR negotiation check).
      ours: src/tls (ServerHello/HRR key_share validation) — verdict: ? — test: — commit: — perf: —
- [ ] V-0244 CVE-2026-11936 (wolfssl) extension-parsing: DoS via memory leak from multiple KeyShareEntry with same group.
      ours: src/tls (key_share extension parsing) — verdict: ? — test: — commit: — perf: —
- [ ] V-0245 CVE-2026-11933 (wolfssl) extension-parsing: DoS from duplicate cookie/CKS extensions causing memory leak.
      ours: src/tls (extension parsing, duplicate detection) — verdict: ? — test: — commit: — perf: —
- [ ] V-0246 CVE-2026-11935 (wolfssl) key-schedule: PSK with PFS downgrades to PSK without PFS.
      ours: src/tls (PSK mode negotiation) — verdict: ? — test: — commit: — perf: —
- [ ] V-0247 CVE-2026-11934 (wolfssl) key-schedule: ECDSA signature algorithm downgrade from P521 to P256 accepted.
      ours: src/tls (signature_algorithms negotiation) — verdict: ? — test: — commit: — perf: —
- [ ] V-0248 CVE-2026-11932 (wolfssl) timing-side-channel: Timing side-channel in PSK binder verification.
      ours: src/tls (PSK binder verification, 0-RTT) — verdict: ? — test: — commit: — perf: —
- [ ] V-0249 CVE-2024-5814 (wolfssl) key-schedule: TLS 1.2 server forces TLS 1.3 downgrade to an unagreed ciphersuite.
      ours: src/tls (version/ciphersuite negotiation) — verdict: ? — test: — commit: — perf: —
- [ ] V-0250 CVE-2024-0901 (wolfssl) extension-parsing: Denial of service and out-of-bounds read in TLS 1.3 server handshake processing.
      ours: src/tls (TLS 1.3 server handshake message parsing) — verdict: ? — test: — commit: — perf: —
- [ ] V-0251 CVE-2023-3724 (wolfssl) key-schedule: TLS 1.3 client uses a predictable default buffer that could compromise session confidentiality.
      ours: src/tls (session/key material buffer init) — verdict: ? — test: — commit: — perf: —
- [ ] V-0252 CVE-2022-42905 (wolfssl) extension-parsing: Heap over-read in TLS 1.3 with WOLFSSL_CALLBACKS macro during handshake message processing.
      ours: src/tls (handshake message parsing) — verdict: ? — test: — commit: — perf: —
- [ ] V-0253 CVE-2022-39173 (wolfssl) 0rtt-replay: DoS and buffer overflow in TLS 1.3 session ticket resumption handling.
      ours: src/tls (session ticket / resumption parsing) — verdict: ? — test: — commit: — perf: —
- [ ] V-0254 CVE-2022-25640 (wolfssl) key-schedule: TLS 1.3 mutual authentication bypassed without certificate_verify processing.
      ours: src/tls (mutual auth / CertificateVerify handling) — verdict: ? — test: — commit: — perf: —
- [ ] V-0255 CVE-2022-25638 (wolfssl) key-schedule: TLS 1.3 certificate check bypassed via signature_algorithms mismatch handling.
      ours: src/tls (CertificateVerify signature algorithm check) — verdict: ? — test: — commit: — perf: —
- [ ] V-0256 CVE-2021-3336 (wolfssl) key-schedule: TLS 1.3 client MITM via authentication bypass in handshake verification.
      ours: src/tls (handshake auth verification) — verdict: ? — test: — commit: — perf: —
- [ ] V-0257 CVE-2020-24613 (wolfssl) key-schedule: TLS 1.3 client MITM authentication bypass.
      ours: src/tls (handshake auth verification) — verdict: ? — test: — commit: — perf: —
- [ ] V-0258 CVE-2020-12457 (wolfssl) transcript: TLS 1.3 server DoS from repeated ChangeCipherSpec messages.
      ours: src/tls (TLS 1.3 state machine, spurious CCS handling) — verdict: ? — test: — commit: — perf: —
- [ ] V-0259 CVE-2019-11873 (wolfssl) extension-parsing: TLS 1.3 PSK extension parsing buffer overflow.
      ours: src/tls (PSK extension parsing) — verdict: ? — test: — commit: — perf: —
- [ ] V-0260 CVE-2026-25832 (mbedtls) key-schedule: TLS 1.3 client accepts HelloRetryRequest selecting a group the client did not advertise support for.
      ours: src/tls (HelloRetryRequest group validation) — verdict: ? — test: — commit: — perf: —
- [ ] V-0261 CVE-2026-73096 (mbedtls) 0rtt-replay: TLS 1.3 early data integrity failure due to buffered plaintext retained across a key change.
      ours: src/tls (0-RTT early data buffering across key update) — verdict: ? — test: — commit: — perf: —
- [ ] V-0262 CVE-2026-50586 (mbedtls) key-schedule: Information disclosure in TLS 1.2 NewSessionTicket processing.
      ours: src/tls (session ticket processing) — verdict: ? — test: — commit: — perf: —
- [ ] V-0263 CVE-2026-50640 (mbedtls) key-schedule: Ignored TLS 1.3 resumption secret derivation error, enabling session forgery.
      ours: src/tls (resumption secret / key schedule error handling) — verdict: ? — test: — commit: — perf: —
- [ ] V-0264 CVE-2026-50581 (mbedtls) key-schedule: Extended master secret calculation failure ignored, weakening TLS 1.2 handshakes (Triple Handshake class).
      ours: src/tls (extended master secret / transcript binding) — verdict: ? — test: — commit: — perf: —
- [ ] V-0265 CVE-2026-34873 (mbedtls) key-schedule: Client impersonation while resuming a TLS 1.3 session (insufficient resumption binding).
      ours: src/tls (session resumption / PSK binder verification) — verdict: ? — test: — commit: — perf: —
- [ ] V-0266 N-2025-03-authbypass (mbedtls) key-schedule: Potential authentication bypass in TLS handshake.
      ours: src/tls (handshake authentication step) — verdict: ? — test: — commit: — perf: —
- [ ] V-0267 N-2025-03-skipserverauth (mbedtls) key-schedule: TLS clients may unwittingly skip server authentication (certificate verification accidentally disabled).
      ours: src/tls (server cert verification enable/disable path) — verdict: ? — test: — commit: — perf: —
- [ ] V-0268 N-2024-08-tls13clientauthbypass (mbedtls) key-schedule: Limited authentication bypass in TLS 1.3 optional client authentication.
      ours: src/tls (TLS 1.3 client auth, CertificateVerify) — verdict: ? — test: — commit: — perf: —
- [ ] V-0269 N-2023-10-ecdhoverflow (mbedtls) extension-parsing: Buffer overflow in TLS handshake parsing with ECDH key exchange.
      ours: src/tls (ECDHE key exchange message parsing) — verdict: ? — test: — commit: — perf: —
- [ ] V-0270 N-2020-09-dhepsk (mbedtls) key-schedule: Protocol weakness in DHE-PSK key exchange lacking contributory behaviour.
      ours: src/tls (PSK key exchange, out of DH scope but pattern relevant) — verdict: ? — test: — commit: — perf: —
- [ ] V-0271 CVE-2026-42010 (gnutls) extension-parsing: Authentication bypass in RSA-PSK servers: usernames containing NUL characters matched truncated variants.
      ours: src/tls (PSK identity/username string handling, NUL-termination) — verdict: ? — test: — commit: — perf: —
- [ ] V-0272 CVE-2026-1584 (gnutls) extension-parsing: Invalid pointer access with TLS 1.3 resumption and a malformed PSK binder in ClientHello.
      ours: src/tls (PSK binder parsing / resumption) — verdict: ? — test: — commit: — perf: —
- [ ] V-0273 CVE-2025-6395 (gnutls) key-schedule: NULL pointer dereference in TLS 1.3 Hello Retry Request handling when PSK is omitted in the second ClientHello
      ours: src/tls (HelloRetryRequest / second ClientHello PSK handling) — verdict: ? — test: — commit: — perf: —
- [ ] V-0274 CVE-2024-0553 (gnutls) timing-side-channel: Timing side-channel in RSA-PSK key exchange (incomplete fix of CVE-2023-5981).
      ours: src/tls (RSA-PSK premaster handling) + src/crypto/asymmetric/rsa — verdict: ? — test: — commit: — perf: —
- [ ] V-0275 CVE-2023-5981 (gnutls) timing-side-channel: Timing side-channel in RSA-PSK key exchange: response time differences between malformed and properly-padded c
      ours: src/tls (RSA-PSK) + src/crypto/asymmetric/rsa — verdict: ? — test: — commit: — perf: —
- [ ] V-0276 CVE-2021-20231 (gnutls) extension-parsing: Use-after-free in TLS 1.3 with large ClientHello messages: key_share extension dereferenced invalid pointer af
      ours: src/tls (key_share extension buffer growth/realloc) — verdict: ? — test: — commit: — perf: —
- [ ] V-0277 CVE-2021-20232 (gnutls) extension-parsing: Use-after-free in TLS 1.3 with large ClientHello messages: pre_shared_key extension dereferenced invalid point
      ours: src/tls (pre_shared_key extension buffer growth/realloc) — verdict: ? — test: — commit: — perf: —
- [ ] V-0278 CVE-2020-24659 (gnutls) transcript: NULL pointer dereference in TLS 1.3 client error handling after a server no_renegotiation alert followed by an
      ours: src/tls (post-handshake alert / state machine error path) — verdict: ? — test: — commit: — perf: —
- [ ] V-0279 CVE-2020-13777 (gnutls) key-schedule: TLS server failed to securely construct the session ticket encryption key, enabling MitM authentication bypass
      ours: src/tls (session ticket key derivation) — verdict: ? — test: — commit: — perf: —
- [ ] V-0280 CVE-2019-3836 (gnutls) extension-parsing: Invalid pointer access with malformed TLS 1.3 handshake messages causing a server crash.
      ours: src/tls (TLS 1.3 handshake message decode) — verdict: ? — test: — commit: — perf: —
- [ ] V-0281 N-libressl-sslclear-uaf (libressl) transcript: Double free or use-after-free could occur after SSL_clear.
      ours: src/tls (session/connection state reset) — verdict: ? — test: — commit: — perf: —
- [ ] V-0282 N-nss-tls13-ccs-dos (nss) transcript: NSS mishandled repeated ChangeCipherSpec messages in TLS 1.3, allowing remote DoS.
      ours: src/tls (TLS 1.3 state machine, spurious CCS handling) — verdict: ? — test: — commit: — perf: —
- [ ] V-0283 CVE-2026-16317 (s2n-tls) extension-parsing: Vulnerability affecting all versions through v1.7.5, fixed in v1.7.6 (details limited from source).
      ours: src/tls (needs advisory detail to map precisely) — verdict: ? — test: — commit: — perf: —
- [ ] V-0284 CVE-2026-34582 (botan) transcript: TLS 1.3 client authentication bypass: ApplicationData records processed before Finished message receipt, letti
      ours: src/tls (TLS 1.3 state machine, Finished-before-appdata ordering) — verdict: ? — test: — commit: — perf: —
- [ ] V-0285 CVE-2018-9860 (botan) der-length-overflow: Off-by-one error in TLS CBC decryption caused HMAC computation over 64KB of data beyond the buffer boundary fo
      ours: src/tls (CBC not in our cipher scope; buffer-bounds pattern relevant to AEAD record parsing) — verdict: ? — test: — commit: — perf: —
- [ ] V-0286 CVE-2020-26939 (bc-java) timing-side-channel: Weak Bleichenbacher oracle in BouncyCastle TLS when using RSA key exchange (prior to 1.0.3 of the TLS module).
      ours: src/tls (RSA key exchange) + src/crypto/asymmetric/rsa — verdict: ? — test: — commit: — perf: —
- [ ] V-0287 CVE-2024-32650 (rustls) transcript: rustls::ConnectionCommon::complete_io could fall into an infinite loop based on network input, affecting rustl
      ours: src/tls (record/handshake I/O loop termination) — verdict: ? — test: — commit: — perf: —
- [ ] V-0288 GHSA-qg5g-gv98-5ffh (rustls) extension-parsing: Network-reachable panic in Acceptor::accept when the received TLS ClientHello is fragmented (rustls 0.23.13-0.
      ours: src/tls (ClientHello reassembly across the Acceptor path) — verdict: ? — test: — commit: — perf: —
- [ ] V-0289 CVE-2021-34558 (go-crypto-tls) key-schedule: crypto/tls clients can panic when a server agrees to an RSA-based key exchange but sends a certificate of an u
      ours: src/tls (key exchange, certificate public-key type check) — verdict: ? — test: — commit: — perf: —
- [ ] V-0290 CVE-2022-30629 (go-crypto-tls) key-schedule: Non-random ticket_age_add in TLS 1.3 session tickets (crypto/tls before Go 1.17.11/1.18.3): ageAdd was always 
      ours: src/tls (NewSessionTicket ageAdd generation) — verdict: ? — test: — commit: — perf: —
- [ ] V-0291 CVE-2022-41724 (go-crypto-tls) extension-parsing: Large handshake records (over the maximum plaintext record size) may cause panics in crypto/tls.
      ours: src/tls (record layer / handshake message size limit enforcement) — verdict: ? — test: — commit: — perf: —
- [ ] V-0292 CVE-2020-1968 (openssl (protocol: TLS DH(E))) timing-side-channel: Raccoon attack: TLS-DH(E) key exchange leaks whether the leading byte of the premaster secret is zero via a ti
      ours: not directly applicable: our SDK is QUIC/TLS1.3-only with (EC)DHE not static/reused DH; kept for the general 'leading-zero-strip creates a timing oracle' pattern relevant to our X25519/ECDH shared-secret handling — verdict: ? — test: — commit: — perf: —
- [ ] V-0293 CVE-2021-3618 (TLS servers supporting wildcard/multi-domain certs (ALPACA)) hostname-mismatch: ALPACA: application-layer protocol confusion. TLS does not cryptographically bind a connection to the intended
      ours: not directly our SDK's job (protocol binding is an application/deployment concern per docs/security.md), but ALPN enforcement in src/tls is the SDK-level mitigation — verdict: ? — test: — commit: — perf: —
- [ ] V-0294 CVE-2015-7575 (TLS 1.2 (protocol, multiple implementations)) transcript: SLOTH: transcript collision attacks exploiting continued support for MD5/SHA-1 (and truncated MAC/hash constru
      ours: src/tls (signature_algorithms / transcript hash negotiation; our SDK is TLS 1.3-only which mandates SHA-256/384 in the transcript, so this class is structurally excluded, but the negotiation-downgrade pattern is worth a regression test) — verdict: ? — test: — commit: — perf: —
- [ ] V-0295 L-tls13-0rtt-replay (TLS 1.3 0-RTT / early data (protocol-level, all implementations)) 0rtt-replay: TLS 1.3 0-RTT early data has no protocol-level replay protection: a network attacker can capture and resend a 
      ours: src/tls (0-RTT server-side: must expose early-data-was-used status to the application layer per docs/security.md, and should support ticket single-use / anti-replay window per RFC 8446 8.1-8.2) — verdict: ? — test: — commit: — perf: —
- [ ] V-0296 CVE-2021-3449 (openssl) extension-parsing: TLS server NULL pointer dereference crash: a TLSv1.2 renegotiation ClientHello that omits signature_algorithms
      ours: src/tls (signature_algorithms/signature_algorithms_cert extension state across renegotiation; our SDK is TLS1.3-only so renegotiation doesn't apply, but re-parsing a second ClientHello's extensions -- e.g. after HelloRetryRequest -- must not assume the first ClientHello's extension state persists) — verdict: ? — test: — commit: — perf: —
- [ ] V-0297 CVE-2020-1967 (openssl) extension-parsing: SSL_check_chain() NULL pointer dereference during a TLS 1.3 handshake when an invalid or unrecognized signatur
      ours: src/tls (signature_algorithms negotiation / CertificateVerify algorithm validation must reject unknown algorithm IDs before dereferencing an algorithm-specific handler) — verdict: ? — test: — commit: — perf: —
- [ ] V-0298 CVE-2024-2511 (openssl) key-schedule: Unbounded memory growth in TLS 1.3 server session cache when the non-default SSL_OP_NO_TICKET option is enable
      ours: src/tls (TLS 1.3 session cache / session-ticket-disabled session storage must still be bounded) — verdict: ? — test: — commit: — perf: —
- [ ] V-0299 CVE-2025-66199 (openssl) extension-parsing: TLS 1.3 CompressedCertificate (certificate compression extension) processing allows per-connection memory allo
      ours: src/tls (certificate_compression extension: decompressed-size bound must be enforced independent of any pre-decompression length field) — verdict: ? — test: — commit: — perf: —
- [ ] V-0300 L-0026 (Selfie: reflection attack on T) psk-reflection: 
      ours: psk-reflection — verdict: ? — test: — commit: — perf: —
- [ ] V-0301 L-0027 (TLS 1.3 0-RTT early-data repla) zero-rtt-replay: 
      ours: zero-rtt-replay — verdict: ? — test: — commit: — perf: —
- [ ] V-0302 S-9001-9.1-1 (RFC 9001) Session linkability via TLS session tickets: Implementations concerned with linkability should consider ticket lifetime/reuse policy; s
      ours: traffic-analysis — verdict: ? — test: — commit: — perf: —
- [ ] V-0303 S-9001-9.2-1 (RFC 9001) 0-RTT replay exposure inherited from TLS 1.3: Endpoints MUST implement and use the replay protections described in TLS 1.3, though these
      ours: 0rtt-replay — verdict: ? — test: — commit: — perf: —
- [ ] V-0304 S-9001-9.2-2 (RFC 9001) QUIC transport state itself is not replay-vulnerable: QUIC is not vulnerable to replay attack except via the application protocol information it
      ours: 0rtt-replay — verdict: ? — test: — commit: — perf: —
- [ ] V-0305 S-9001-9.2-3 (RFC 9001) Session tickets and address-validation tokens must not carry application semantics: Session tickets and address validation tokens MUST NOT be used to communicate application 
      ours: 0rtt-replay — verdict: ? — test: — commit: — perf: —
- [ ] V-0306 S-9001-9.2-4 (RFC 9001) Cost asymmetry of accepting 0-RTT: Servers need to consider the probability of replay and all associated costs when deciding 
      ours: 0rtt-replay — verdict: ? — test: — commit: — perf: —
- [ ] V-0307 S-9001-9.2-5 (RFC 9001) Application protocol responsibility for 0-RTT replay mitigation: The application protocol using QUIC MUST describe how it uses 0-RTT and the measures emplo
      ours: 0rtt-replay — verdict: ? — test: — commit: — perf: —
- [ ] V-0308 S-9001-9.2-6 (RFC 9001) Disabling 0-RTT as the strongest replay defense: Disabling 0-RTT entirely is the most effective defense against replay attack.
      ours: 0rtt-replay — verdict: ? — test: — commit: — perf: —
- [ ] V-0309 S-9001-9.2-7 (RFC 9001) Extensions must address 0-RTT replay: QUIC extensions MUST either describe how replay attacks affect their operation or prohibit
      ours: 0rtt-replay — verdict: ? — test: — commit: — perf: —
- [ ] V-0310 S-9001-9.3-1 (RFC 9001) Packet reflection/amplification via small ClientHello: QUIC includes three defenses: the packet containing a ClientHello MUST be padded to a mini
      ours: amplification — verdict: ? — test: — commit: — perf: —
- [ ] V-0311 S-9001-9.3-2 (RFC 9001) Combined effect of the three defenses: Put together, these three defenses limit the level of amplification achievable, even thoug
      ours: amplification — verdict: ? — test: — commit: — perf: —
- [ ] V-0312 S-9001-9.4-1 (RFC 9001) Header protection construction analysis (HN1 / Hide Nonce): The general header protection construction (encrypting header fields via a PRF applied to 
      ours: header-protection-bypass — verdict: ? — test: — commit: — perf: —
- [ ] V-0313 S-9001-9.4-2 (RFC 9001) AE2 security guarantee of header protection: Because hp_key is distinct from the packet protection key, header protection achieves AE2 
      ours: header-protection-bypass — verdict: ? — test: — commit: — perf: —
- [ ] V-0314 S-9001-9.4-3 (RFC 9001) Header protection sample/key reuse risk: Assuming the AEAD acts as a PRF, if L bits are sampled, the odds of two ciphertext samples
      ours: nonce-reuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0315 S-9001-9.4-4 (RFC 9001) Header field tampering detection via transitive authentication: To prevent an attacker from modifying packet headers, the header is transitively authentic
      ours: header-protection-bypass — verdict: ? — test: — commit: — perf: —
- [ ] V-0316 S-9001-9.5-1 (RFC 9001) Timing side channel from guessing packet number / Key Phase: For authentication to be free from side channels, the entire process of header protection 
      ours: timing-side-channel — verdict: ? — test: — commit: — perf: —
- [ ] V-0317 S-9001-9.5-2 (RFC 9001) Sending-side timing side channel on packet number encoding: Construction and protection of packet payloads and packet numbers MUST be free from side c
      ours: timing-side-channel — verdict: ? — test: — commit: — perf: —
- [ ] V-0318 S-9001-9.5-3 (RFC 9001) Key update timing side channel on Key Phase: After receiving a key update, an endpoint SHOULD generate and save the next set of receive
      ours: key-update — verdict: ? — test: — commit: — perf: —
- [ ] V-0319 S-9001-9.5-4 (RFC 9001) Key-set bookkeeping to avoid the key-update timing side channel: Avoiding the side channel requires not performing key generation during packet processing 
      ours: key-update — verdict: ? — test: — commit: — perf: —
- [ ] V-0320 S-9001-9.6-1 (RFC 9001) Key separation between QUIC and TLS via distinct labels: QUIC uses labels distinct from TLS's own key derivation labels (e.g. 'quic key', 'quic iv'
      ours: key-diversity — verdict: ? — test: — commit: — perf: —
- [ ] V-0321 S-9001-9.7-1 (RFC 9001) Requirement for cryptographically secure randomness: Endpoints MUST use a cryptographically secure random number generator for generating conne
      ours: weak-randomness — verdict: ? — test: — commit: — perf: —
- [ ] V-0322 S-8446-10-1 (RFC 8446) Security considerations pointer: Implementers MUST consult Appendices C, D, and E, which contain the concrete security guid
      ours: documentation-pointer — verdict: ? — test: — commit: — perf: —
- [ ] V-0323 S-8446-C.1-1 (RFC 8446) Weak or predictable CSPRNG: Use a cryptographically secure PRNG (e.g. /dev/urandom or an established CSPRNG library) r
      ours: weak-rng — verdict: ? — test: — commit: — perf: —
- [ ] V-0324 S-8446-C.2-1 (RFC 8446) Improper certificate/trust-anchor validation: Implementations SHOULD support certificate revocation, verify signing by a trusted CA, let
      ours: cert-validation — verdict: ? — test: — commit: — perf: —
- [ ] V-0325 S-8446-C.3-1 (RFC 8446) Implementation pitfalls overview: This appendix enumerates the most important pitfalls implementors must specifically check 
      ours: implementation-pitfall — verdict: ? — test: — commit: — perf: —
- [ ] V-0326 S-8446-C.3-2 (RFC 8446) Mishandled fragmented handshake messages: Correctly reassemble handshake messages split into multiple records, including corner case
      ours: parser-robustness — verdict: ? — test: — commit: — perf: —
- [ ] V-0327 S-8446-C.3-3 (RFC 8446) Trusting the record layer version number: Implementations MUST ignore the TLS record layer version number in all unencrypted TLS rec
      ours: downgrade-attack — verdict: ? — test: — commit: — perf: —
- [ ] V-0328 S-8446-C.3-4 (RFC 8446) Leftover support for SSL/RC4/EXPORT/MD5: Ensure all support for SSL, RC4, EXPORT ciphers, and MD5 (via signature_algorithms) is com
      ours: downgrade-attack — verdict: ? — test: — commit: — perf: —
- [ ] V-0329 S-8446-C.3-5 (RFC 8446) Mishandling unknown ClientHello extensions: Implementations must handle TLS extensions in ClientHellos correctly, including unknown/un
      ours: parser-robustness — verdict: ? — test: — commit: — perf: —
- [ ] V-0330 S-8446-C.3-6 (RFC 8446) Omitting empty Certificate message: When no suitable certificate is available in response to a CertificateRequest, the client 
      ours: protocol-state-confusion — verdict: ? — test: — commit: — perf: —
- [ ] V-0331 S-8446-C.3-7 (RFC 8446) Out-of-bounds scan for ContentType in AEAD-decrypted plaintext: Implementations must bound the scan and avoid reading before the start of the cleartext wh
      ours: buffer-overread — verdict: ? — test: — commit: — perf: —
- [ ] V-0332 S-8446-C.3-8 (RFC 8446) Rejecting on unrecognized negotiation values: Implementations must properly ignore unrecognized cipher suites, hello extensions, named g
      ours: parser-robustness — verdict: ? — test: — commit: — perf: —
- [ ] V-0333 S-8446-C.3-9 (RFC 8446) Missing/incorrect HelloRetryRequest handling: Servers should send HelloRetryRequest appropriately for compatible-but-unpredicted groups;
      ours: protocol-state-confusion — verdict: ? — test: — commit: — perf: —
- [ ] V-0334 S-8446-C.3-10 (RFC 8446) Cryptographic implementation pitfalls (heading): See following per-item defenses.
      ours: implementation-pitfall — verdict: ? — test: — commit: — perf: —
- [ ] V-0335 S-8446-C.3-11 (RFC 8446) Timing side channels in cryptographic operations: Implementations should use constant-time or otherwise timing-attack-resistant cryptographi
      ours: timing-side-channel — verdict: ? — test: — commit: — perf: —
- [ ] V-0336 S-8446-C.3-12 (RFC 8446) Dropped leading zero bytes in DH key: Correctly preserve leading zero bytes in the negotiated Diffie-Hellman key.
      ours: encoding-inconsistency — verdict: ? — test: — commit: — perf: —
- [ ] V-0337 S-8446-C.3-13 (RFC 8446) Unvalidated Diffie-Hellman parameters: TLS clients should check that DH parameters sent by the server are acceptable per Section 
      ours: invalid-curve — verdict: ? — test: — commit: — perf: —
- [ ] V-0338 S-8446-C.3-14 (RFC 8446) Improperly seeded values for DH/ECDSA secrets: Use a strong, properly seeded RNG per Appendix C.1; RECOMMENDED to implement deterministic
      ours: nonce-reuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0339 S-8446-C.3-15 (RFC 8446) Missing zero-padding of DH public values/secrets: Zero-pad Diffie-Hellman public key values and shared secrets to the group size per Section
      ours: encoding-inconsistency — verdict: ? — test: — commit: — perf: —
- [ ] V-0340 S-8446-C.3-16 (RFC 8446) Missing signature verification after signing (RSA-CRT leak): Verify signatures after making them to protect against RSA-CRT key leaks.
      ours: fault-attack — verdict: ? — test: — commit: — perf: —
- [ ] V-0341 S-8446-C.4-1 (RFC 8446) Session-ticket-based client tracking: Clients SHOULD NOT reuse a ticket for multiple connections; servers SHOULD issue at least 
      ours: session-linkability — verdict: ? — test: — commit: — perf: —
- [ ] V-0342 S-8446-C.5-1 (RFC 8446) Silent lack of server authentication via raw public keys or unvalidated certs: If no external authentication mechanism (out-of-band key validation, trust-on-first-use, o
      ours: missing-authentication — verdict: ? — test: — commit: — perf: —
- [ ] V-0343 S-8446-D-1 (RFC 8446) Version-negotiation compatibility overview: Endpoints negotiate using the handshake version fields and supported_versions extension ra
      ours: downgrade-attack — verdict: ? — test: — commit: — perf: —
- [ ] V-0344 S-8446-D-2 (RFC 8446) Legacy ClientHello compatibility assumption: Servers should only proceed if there is at least one protocol version supported by both cl
      ours: downgrade-attack — verdict: ? — test: — commit: — perf: —
- [ ] V-0345 S-8446-D-3 (RFC 8446) Legacy record-layer version field reliance: The value of TLSPlaintext.legacy_record_version MUST be ignored by all implementations; TL
      ours: downgrade-attack — verdict: ? — test: — commit: — perf: —
- [ ] V-0346 S-8446-D-4 (RFC 8446) Certification path validation gaps for older handshakes: Implementations SHOULD support validation of certification paths per this document's expec
      ours: cert-validation — verdict: ? — test: — commit: — perf: —
- [ ] V-0347 S-8446-D-5 (RFC 8446) Missing Extended Master Secret indication: Implementations supporting both TLS 1.3 and earlier SHOULD indicate use of the Extended Ma
      ours: api-security-signal — verdict: ? — test: — commit: — perf: —
- [ ] V-0348 S-8446-D.1-1 (RFC 8446) Downgrade during negotiation with an older server: Client sends legacy_version 0x0303 with actual versions in supported_versions; a resuming 
      ours: downgrade-attack — verdict: ? — test: — commit: — perf: —
- [ ] V-0349 S-8446-D.1-2 (RFC 8446) 0-RTT sent to a server that doesn't support TLS 1.3: 0-RTT data SHOULD NOT be sent absent knowledge that the server supports TLS 1.3 (see Appen
      ours: 0rtt-replay — verdict: ? — test: — commit: — perf: —
- [ ] V-0350 S-8446-D.1-3 (RFC 8446) Unvalidated server-chosen version: If the version chosen by the server is not supported or acceptable to the client, the clie
      ours: downgrade-attack — verdict: ? — test: — commit: — perf: —
- [ ] V-0351 S-8446-D.1-4 (RFC 8446) Repeated reconnection attempts against buggy legacy servers: This fallback-retry practice is NOT RECOMMENDED precisely because of its downgrade-attack 
      ours: downgrade-attack — verdict: ? — test: — commit: — perf: —
- [ ] V-0352 S-8446-D.2-1 (RFC 8446) Improper server-side version selection for older clients: If supported_versions is present the server MUST negotiate using it; if absent the server 
      ours: downgrade-attack — verdict: ? — test: — commit: — perf: —
- [ ] V-0353 S-8446-D.2-2 (RFC 8446) Trusting legacy_record_version from old clients: Servers MUST always ignore the value of TLSPlaintext.legacy_record_version.
      ours: downgrade-attack — verdict: ? — test: — commit: — perf: —
- [ ] V-0354 S-8446-D.3-1 (RFC 8446) 0-RTT data sent to a downgraded/mixed-version deployment: Multi-server deployments risk this scenario during partial rollout or downgrade of TLS 1.3
      ours: 0rtt-replay — verdict: ? — test: — commit: — perf: —
- [ ] V-0355 S-8446-D.3-2 (RFC 8446) Automatic 0-RTT retry causing downgrade of the whole connection: A client MUST fail the connection if it receives a ServerHello with TLS 1.2 or older after
      ours: downgrade-attack — verdict: ? — test: — commit: — perf: —
- [ ] V-0356 S-8446-D.3-3 (RFC 8446) Non-uniform TLS 1.3 rollout across a server fleet enabling 0-RTT errors: Multi-server deployments SHOULD ensure uniform and stable TLS 1.3 deployment without 0-RTT
      ours: 0rtt-replay — verdict: ? — test: — commit: — perf: —
- [ ] V-0357 S-8446-D.4-1 (RFC 8446) Middlebox interference breaking TLS 1.3 handshakes: Implementations can adopt compatibility-mode behaviors (non-empty session ID, dummy change
      ours: protocol-interop-dos — verdict: ? — test: — commit: — perf: —
- [ ] V-0358 S-8446-D.4-2 (RFC 8446) Non-empty session ID echo requirement: The client always provides a non-empty session ID in compatibility mode; the mechanism is 
      ours: protocol-interop-dos — verdict: ? — test: — commit: — perf: —
- [ ] V-0359 S-8446-D.4-3 (RFC 8446) Missing dummy change_cipher_spec placement: Client sends the dummy record before its second flight (or after first ClientHello if usin
      ours: protocol-interop-dos — verdict: ? — test: — commit: — perf: —
- [ ] V-0360 S-8446-D.4-4 (RFC 8446) Inconsistent compatibility-mode negotiation between peers: If the client sends a non-empty session ID, the server MUST send the change_cipher_spec re
      ours: protocol-interop-dos — verdict: ? — test: — commit: — perf: —
- [ ] V-0361 S-8446-D.5-1 (RFC 8446) Weak cipher suite preference when negotiating older TLS: Implementations negotiating older TLS versions SHOULD prefer forward-secret and AEAD ciphe
      ours: weak-cipher-negotiation — verdict: ? — test: — commit: — perf: —
- [ ] V-0362 S-8446-D.5-2 (RFC 8446) RC4 cipher suite negotiation: Implementations MUST NOT offer or negotiate RC4 cipher suites for any version of TLS for a
      ours: weak-cipher-negotiation — verdict: ? — test: — commit: — perf: —
- [ ] V-0363 S-8446-D.5-3 (RFC 8446) Low-strength cipher negotiation: Ciphers with strength less than 112 bits MUST NOT be offered or negotiated for any TLS ver
      ours: weak-cipher-negotiation — verdict: ? — test: — commit: — perf: —
- [ ] V-0364 S-8446-D.5-4 (RFC 8446) SSL 3.0 negotiation (POODLE-class attacks): SSL 3.0 MUST NOT be negotiated for any reason.
      ours: downgrade-attack — verdict: ? — test: — commit: — perf: —
- [ ] V-0365 S-8446-D.5-5 (RFC 8446) SSL 2.0 negotiation: SSL 2.0 MUST NOT be negotiated for any reason.
      ours: downgrade-attack — verdict: ? — test: — commit: — perf: —
- [ ] V-0366 S-8446-D.5-6 (RFC 8446) SSLv2-compatible ClientHello abuse: Implementations MUST NOT send an SSLv2-compatible CLIENT-HELLO, MUST NOT negotiate TLS 1.3
      ours: cross-protocol-attack — verdict: ? — test: — commit: — perf: —
- [ ] V-0367 S-8446-D.5-7 (RFC 8446) Pre-SSL-3.0 legacy_version values: Implementations MUST NOT send legacy_version <= 0x0300; any endpoint receiving such a valu
      ours: downgrade-attack — verdict: ? — test: — commit: — perf: —
- [ ] V-0368 S-8446-D.5-8 (RFC 8446) Pre-SSL-3.0 record version values: Implementations MUST NOT send records with version < 0x0300, and SHOULD NOT accept such re
      ours: downgrade-attack — verdict: ? — test: — commit: — perf: —
- [ ] V-0369 S-8446-D.5-9 (RFC 8446) Truncated HMAC extension usage: Implementations MUST NOT use the Truncated HMAC extension.
      ours: weak-mac-truncation — verdict: ? — test: — commit: — perf: —
- [ ] V-0370 S-8446-E.1-1 (RFC 8446) Handshake AKE goals overview: The handshake is designed to provide the listed properties even under a fully active netwo
      ours: threat-model — verdict: ? — test: — commit: — perf: —
- [ ] V-0371 S-8446-E.1-2 (RFC 8446) Session key establishment mismatch: The handshake needs to output the same set of session keys on both sides when it completes
      ours: key-agreement-failure — verdict: ? — test: — commit: — perf: —
- [ ] V-0372 S-8446-E.1-3 (RFC 8446) Session key secrecy failure: The shared session keys must be known only to the communicating parties, not the attacker;
      ours: key-secrecy — verdict: ? — test: — commit: — perf: —
- [ ] V-0373 S-8446-E.1-4 (RFC 8446) Peer authentication mismatch: The client's view of peer identity should reflect the server's actual identity, and vice v
      ours: authentication-bypass — verdict: ? — test: — commit: — perf: —
- [ ] V-0374 S-8446-E.1-5 (RFC 8446) Session key reuse across handshakes: Any two distinct handshakes should produce distinct, unrelated session keys; individual ke
      ours: key-reuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0375 S-8446-E.1-6 (RFC 8446) Downgrade of cryptographic parameters: Cryptographic parameters should be identical on both sides and the same as if no attacker 
      ours: downgrade-attack — verdict: ? — test: — commit: — perf: —
- [ ] V-0376 S-8446-E.1-7 (RFC 8446) Long-term key compromise breaking past sessions (lack of forward secrecy): Session keys should remain secure even if long-term keys are later compromised, provided t
      ours: key-reuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0377 S-8446-E.1-8 (RFC 8446) Lack of Key Compromise Impersonation (KCI) resistance: Mutually authenticated certificate-based connections should resist KCI: compromising one a
      ours: key-compromise-impersonation — verdict: ? — test: — commit: — perf: —
- [ ] V-0378 S-8446-E.1-9 (RFC 8446) Endpoint identity exposure: The server's identity should be protected against passive attackers; the client's identity
      ours: identity-exposure — verdict: ? — test: — commit: — perf: —
- [ ] V-0379 S-8446-E.1-10 (RFC 8446) Signature-based mode design rationale: Fresh (EC)DHE keys per connection yield forward secrecy in signature-based modes.
      ours: key-agreement-failure — verdict: ? — test: — commit: — perf: —
- [ ] V-0380 S-8446-E.1-11 (RFC 8446) PSK forward secrecy dependent on (EC)DHE use: PSK with (EC)DHE key establishment yields forward-secret session keys; the resumption mast
      ours: key-reuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0381 S-8446-E.1-12 (RFC 8446) Cross-ticket compromise via shared resumption structure: Each ticket established on a connection is associated with a different key so that comprom
      ours: key-reuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0382 S-8446-E.1-13 (RFC 8446) PSK binder collision / transcript-binding weakness: The PSK binder cryptographically binds the PSK to the current and original handshake trans
      ours: signature-malleability — verdict: ? — test: — commit: — perf: —
- [ ] V-0383 S-8446-E.1-14 (RFC 8446) Client signature not covering server certificate in non-cert handshakes: If PSK was established via NewSessionTicket the client's signature transitively covers the
      ours: authentication-bypass — verdict: ? — test: — commit: — perf: —
- [ ] V-0384 S-8446-E.1-15 (RFC 8446) Exporter value predictability/collision: Exporters with different labels/contexts are computationally independent; if used as chann
      ours: key-reuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0385 S-8446-E.1-16 (RFC 8446) Downgrade attack detection via Finished MAC and random nonces: The Finished MAC (and signature, where present) prevents downgrade attacks; specific bytes
      ours: downgrade-attack — verdict: ? — test: — commit: — perf: —
- [ ] V-0386 S-8446-E.1-17 (RFC 8446) Identity leakage before encryption begins / via record length: Server authenticates before the client so the client only reveals its identity to an authe
      ours: identity-exposure — verdict: ? — test: — commit: — perf: —
- [ ] V-0387 S-8446-E.1.1-1 (RFC 8446) Improper HKDF-Extract chaining: Each HKDF-Extract application should be followed by one or more HKDF-Expand invocations; i
      ours: key-derivation-misuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0388 S-8446-E.1.1-2 (RFC 8446) Insufficient collision resistance in HKDF-Expand outputs: The underlying hash function must be collision resistant and HKDF-Expand output length mus
      ours: signature-malleability — verdict: ? — test: — commit: — perf: —
- [ ] V-0389 S-8446-E.1.2-1 (RFC 8446) Ambiguity over whether server considers client authenticated: Applications needing to know if a connection is unilaterally or mutually authenticated mus
      ours: authentication-bypass — verdict: ? — test: — commit: — perf: —
- [ ] V-0390 S-8446-E.1.3-1 (RFC 8446) 0-RTT lacks full forward secrecy and replay protection: See Section 8 mechanisms to limit exposure to replay; 1-RTT data properties otherwise most
      ours: 0rtt-replay — verdict: ? — test: — commit: — perf: —
- [ ] V-0391 S-8446-E.1.4-1 (RFC 8446) Exporter master secret compromise exposing all derived exporters: These secrets SHOULD be erased as soon as possible; if the label set is known in advance, 
      ours: key-lifetime-management — verdict: ? — test: — commit: — perf: —
- [ ] V-0392 S-8446-E.1.5-1 (RFC 8446) No post-compromise security after long-term secret compromise: This is a known, accepted limitation (contrasted with KCI resistance, which only covers pr
      ours: post-compromise-security-gap — verdict: ? — test: — commit: — perf: —
- [ ] V-0393 S-8446-E.2-1 (RFC 8446) Record layer security goals overview: AEAD-based record protection is designed to meet these properties when used within the doc
      ours: threat-model — verdict: ? — test: — commit: — perf: —
- [ ] V-0394 S-8446-E.2-2 (RFC 8446) Plaintext confidentiality failure: AEAD encryption with a strong key provides confidentiality for record contents.
      ours: confidentiality-failure — verdict: ? — test: — commit: — perf: —
- [ ] V-0395 S-8446-E.2-3 (RFC 8446) Record forgery / integrity failure: AEAD encryption provides integrity, preventing acceptance of forged records.
      ours: integrity-failure — verdict: ? — test: — commit: — perf: —
- [ ] V-0396 S-8446-E.2-4 (RFC 8446) Replay or reordering of records: A separate nonce per record derived from the record sequence number (maintained independen
      ours: replay-attack — verdict: ? — test: — commit: — perf: —
- [ ] V-0397 S-8446-E.2-5 (RFC 8446) Record length leaking content-vs-padding distinction: Length concealment: the attacker should not be able to distinguish padding from content gi
      ours: traffic-analysis — verdict: ? — test: — commit: — perf: —
- [ ] V-0398 S-8446-E.2-6 (RFC 8446) Loss of forward secrecy after key update if old key retained: After using the traffic key update mechanism (Section 4.6.3) and deleting the previous key
      ours: key-lifetime-management — verdict: ? — test: — commit: — perf: —
- [ ] V-0399 S-8446-E.2-7 (RFC 8446) Nonce construction against mass cryptanalysis: The nonce mixes the sequence number with a secret per-connection initialization vector der
      ours: nonce-reuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0400 S-8446-E.2-8 (RFC 8446) Rekeying construction security: Rely on HKDF-Expand-Label's PRF security and one-wayness; correctly implemented rekeying p
      ours: key-derivation-misuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0401 S-8446-E.2-9 (RFC 8446) No post-compromise security for the record layer / traffic secret: TLS provides no post-compromise/future/backward secrecy for the traffic secret; systems ne
      ours: post-compromise-security-gap — verdict: ? — test: — commit: — perf: —
- [ ] V-0402 S-8446-E.3-1 (RFC 8446) Traffic analysis via length and timing: TLS provides a padding mechanism (arbitrary-length padding on the AEAD-protected plaintext
      ours: traffic-analysis — verdict: ? — test: — commit: — perf: —
- [ ] V-0403 S-8446-E.3-2 (RFC 8446) Timing-channel leakage of padding length: Fully constant-time padding removal is hard because content still feeds into data-dependen
      ours: timing-side-channel — verdict: ? — test: — commit: — perf: —
- [ ] V-0404 S-8446-E.3-3 (RFC 8446) Trade-off of anti-traffic-analysis defenses: Implementers should weigh performance impact when deploying robust traffic-analysis counte
      ours: traffic-analysis — verdict: ? — test: — commit: — perf: —
- [ ] V-0405 S-8446-E.4-1 (RFC 8446) General side-channel exposure left to crypto primitive implementations: TLS 1.3's exclusive use of AEAD algorithms (vs. old MAC-then-encrypt) allows self-containe
      ours: timing-side-channel — verdict: ? — test: — commit: — perf: —
- [ ] V-0406 S-8446-E.4-2 (RFC 8446) Piecewise decryption-error oracle: TLS uses a uniform bad_record_mac alert for all decryption errors and terminates the conne
      ours: padding-oracle — verdict: ? — test: — commit: — perf: —
- [ ] V-0407 S-8446-E.4-3 (RFC 8446) Side-channel leakage above the TLS layer: Resistance to such leakage depends on applications and application protocols separately en
      ours: timing-side-channel — verdict: ? — test: — commit: — perf: —
- [ ] V-0408 S-8446-E.5-1 (RFC 8446) 0-RTT replay causing duplicated side effects: Applications MUST NOT use 0-RTT data unless specifically engineered to be safe under repla
      ours: 0rtt-replay — verdict: ? — test: — commit: — perf: —
- [ ] V-0409 S-8446-E.5-2 (RFC 8446) 0-RTT replay for message reordering: Applications must be engineered to tolerate such reordering or the profile must forbid uns
      ours: 0rtt-replay — verdict: ? — test: — commit: — perf: —
- [ ] V-0410 S-8446-E.5-3 (RFC 8446) Cache-timing content discovery via 0-RTT replay: No direct defense stated beyond general 0-RTT replay mitigations; applications should be a
      ours: timing-side-channel — verdict: ? — test: — commit: — perf: —
- [ ] V-0411 S-8446-E.5-4 (RFC 8446) Repeated replay enabling crypto timing measurement or rate-limit evasion: See Mac17 for further description; servers must bound replay exposure (see Section 8 mecha
      ours: timing-side-channel — verdict: ? — test: — commit: — perf: —
- [ ] V-0412 S-8446-E.5-5 (RFC 8446) Cross-cluster replay via ClientHello duplication: The scale is limited by the client's willingness to retry transactions, so only a limited 
      ours: 0rtt-replay — verdict: ? — test: — commit: — perf: —
- [ ] V-0413 S-8446-E.5-6 (RFC 8446) Replay tolerance under inconsistent server-side state: Sections 8.1/8.2 mechanisms prevent replay across a cluster with fully consistent state; c
      ours: 0rtt-replay — verdict: ? — test: — commit: — perf: —
- [ ] V-0414 S-8446-E.5-7 (RFC 8446) Unprofiled use of 0-RTT by applications: Application protocols MUST NOT use 0-RTT data without a profile defining which messages/in
      ours: 0rtt-replay — verdict: ? — test: — commit: — perf: —
- [ ] V-0415 S-8446-E.5-8 (RFC 8446) Accidental/implicit 0-RTT enablement or auto-resend: TLS implementations MUST NOT enable 0-RTT (sending or accepting) unless specifically reque
      ours: 0rtt-replay — verdict: ? — test: — commit: — perf: —
- [ ] V-0416 S-8446-E.5.1-1 (RFC 8446) Early exporter reuse across replayed ClientHellos: Applications using the early exporter as a channel binding need additional care given this
      ours: 0rtt-replay — verdict: ? — test: — commit: — perf: —
- [ ] V-0417 S-8446-E.5.1-2 (RFC 8446) Early exporter reused for server-to-client keys: The early exporter SHOULD NOT be used to generate server-to-client encryption keys, parall
      ours: key-reuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0418 S-8446-E.6-1 (RFC 8446) PSK identity validity oracle via handshake abort behavior: Servers that solely support PSK handshakes may resist this by treating 'no valid PSK ident
      ours: psk-identity-oracle — verdict: ? — test: — commit: — perf: —
- [ ] V-0419 S-8446-E.7-1 (RFC 8446) Cross-version PSK reuse between TLS 1.2 and TLS 1.3: Implementations can ensure safety from cross-protocol related output by not reusing PSKs b
      ours: key-reuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0420 S-8446-E.8-1 (RFC 8446) Bleichenbacher-style attack via shared static-RSA support: TLS 1.3 implementations can prevent this by disabling static RSA support across ALL versio
      ours: cross-protocol-attack — verdict: ? — test: — commit: — perf: —

## Symmetric crypto and hashing

- [ ] V-0752 CVE-2022-23408 (wolfssl) nonce-reuse: Non-random IV in AES-CBC/DES3 with TLS/DTLS 1.2 or 1.1 (record encryption).
      ours: src/crypto/symmetric (IV generation for CBC mode) — verdict: ? — test: — commit: — perf: —
- [ ] V-0753 CVE-2026-50584 (mbedtls) nonce-reuse: ChaCha20 counter overflow can cause keystream reuse.
      ours: src/crypto/symmetric/chacha20 (counter overflow) — verdict: ? — test: — commit: — perf: —
- [ ] V-0754 CVE-2026-25835 (mbedtls) nonce-reuse: PSA random generator cloning allows RNG state duplication and keystream prediction.
      ours: out of our AES-GCM/ChaCha component but nonce/keystream-adjacent; n/a to our src (no PSA layer) — verdict: ? — test: — commit: — perf: —
- [ ] V-0755 CVE-2025-59438 (mbedtls) timing-side-channel: Padding oracle through timing of cipher error reporting (decrypt failure timing leaks plaintext structure).
      ours: src/crypto/symmetric (block cipher / AEAD error-path timing) — verdict: ? — test: — commit: — perf: —
- [ ] V-0756 N-2025-06-cbctiming (mbedtls) timing-side-channel: Timing side-channel in block cipher decryption with PKCS#7 padding.
      ours: src/crypto/symmetric (CBC/PKCS7 padding check) — verdict: ? — test: — commit: — perf: —
- [ ] V-0757 N-2020-09-cbcside (mbedtls) timing-side-channel: Local side channel attack on classical CBC decryption in (D)TLS (Lucky13-class).
      ours: src/crypto/symmetric (out of AEAD scope; CBC not in our cipher list, informational) — verdict: ? — test: — commit: — perf: —
- [ ] V-0758 N-nss-chacha20poly1305-oob (nss) der-length-overflow: ChaCha20-Poly1305 implementation before NSS 3.55 caused out-of-bounds reads when using multi-part ChaCha20.
      ours: src/crypto/symmetric/chacha20poly1305 (multi-part/streaming update path) — verdict: ? — test: — commit: — perf: —
- [ ] V-0759 GHSA-7gxc-93xj-596h (s2n-tls) nonce-reuse: Predictable IV in CBC-mode composite cipher suites.
      ours: src/crypto/symmetric (IV generation, CBC not in our cipher scope but nonce-gen pattern relevant) — verdict: ? — test: — commit: — perf: —
- [ ] V-0760 CVE-2021-24115 (botan) timing-side-channel: base64/base58/base32/hex encoding and decoding operations were not constant time.
      ours: src/util (encoding helpers, if any touch key material) — verdict: ? — test: — commit: — perf: —
- [ ] V-0761 CVE-2020-28052 (bc-java) carry-propagation-bug: OpenBSDBcrypt.doFinal has an integer overflow via a length value, related to signature verification bypass pat
      ours: out of scope: bcrypt is not a listed primitive; informational only — verdict: ? — test: — commit: — perf: —
- [ ] V-0762 CVE-2025-4432 (ring) carry-propagation-bug: Some AES functions in ring may panic when overflow checking is enabled (debug builds), reachable via a crafted
      ours: src/crypto/symmetric/aesgcm (block counter arithmetic) — verdict: ? — test: — commit: — perf: —
- [ ] V-0763 L-gcm-nonce-disrespect (AES-GCM in TLS (general, multiple vendors)) nonce-reuse: Nonce-Disrespecting Adversaries (the 'forbidden attack', Joux 2006, revisited USENIX WOOT 2016): reusing an AE
      ours: src/crypto/symmetric/aesgcm (nonce/IV construction: must be unique per key, e.g. via the TLS 1.3 record sequence number XOR construction, RFC 8446 5.3) — verdict: ? — test: — commit: — perf: —
- [ ] V-0764 L-0034 (AES-GCM nonce reuse: the 'Forb) nonce-reuse: 
      ours: nonce-reuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0765 L-0035 (Poly1305 one-time-key reuse en) key-reuse-mac-forgery: 
      ours: key-reuse-mac-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0766 S-8032-8.9-1 (RFC 8032) SHAKE256 truncation-prefix property is acceptable given fixed output length: Because Ed448 uses SHAKE256 with fixed output lengths, the prefix property is acceptable i
      ours: hash-function-substitution — verdict: ? — test: — commit: — perf: —
- [ ] V-0767 S-8032-8.9-2 (RFC 8032) SHAKE256's estimated security suffices for Ed448's target level: SHAKE256's estimated 256-bit security against collisions and preimages suffices for the 22
      ours: hash-function-substitution — verdict: ? — test: — commit: — perf: —
- [ ] V-0768 S-8439-4-1 (RFC 8439) Design security levels of ChaCha20 and Poly1305: ChaCha20 is designed to provide 256-bit security; Poly1305 ensures strong unforgeability, 
      ours: design-overview — verdict: ? — test: — commit: — perf: —
- [ ] V-0769 S-8439-4-2 (RFC 8439) Nonce uniqueness is the most critical implementation requirement: The most important security consideration in implementing this document is the uniqueness 
      ours: nonce-reuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0770 S-8439-4-3 (RFC 8439) Nonce reuse reveals the XOR of plaintexts and forges the MAC key: This is the direct consequence spelled out to motivate the strict nonce-uniqueness require
      ours: nonce-reuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0771 S-8439-4-4 (RFC 8439) Poly1305 one-time key unpredictability requirement: The Poly1305 key MUST be unpredictable to an attacker; random generation works, and pseudo
      ours: weak-randomness — verdict: ? — test: — commit: — perf: —
- [ ] V-0772 S-8439-4-5 (RFC 8439) Timing side channels in ChaCha20/Poly1305 arithmetic: ChaCha20's operations (additions, XORs, fixed rotations) can and should be implemented in 
      ours: timing-side-channel — verdict: ? — test: — commit: — perf: —
- [ ] V-0773 S-8439-4-6 (RFC 8439) Constant-time tag comparison and full-length tag requirement: Implementations MUST use a constant-time comparison function for tag verification; tag tru
      ours: timing-side-channel — verdict: ? — test: — commit: — perf: —
- [ ] V-0774 S-5869-6-1 (RFC 5869) HKDF's simplicity conceals substantial underlying analysis: Despite HKDF's apparent simplicity, numerous security considerations informed its design a
      ours: design-overview — verdict: ? — test: — commit: — perf: —
- [ ] V-0775 S-5869-6-2 (RFC 5869) HKDF designed with care given limited confidence in hash function strength: A major effort has been made to provide a cryptographic analysis of HKDF as a multi-purpos
      ours: hash-function-substitution — verdict: ? — test: — commit: — perf: —
- [ ] V-0776 S-5869-6-3 (RFC 5869) Analysis does not guarantee absolute security: The analysis does not imply the absolute security of any scheme; it depends heavily on the
      ours: hash-function-substitution — verdict: ? — test: — commit: — perf: —
- [ ] V-0777 S-5869-6-4 (RFC 5869) Analysis supports HKDF's structural advantages over ad hoc KDFs: The analysis serves as a strong indication of the correctness of HKDF's structure and its 
      ours: design-overview — verdict: ? — test: — commit: — perf: —
- [ ] V-0778 S-2104-6-1 (RFC 2104) HMAC security depends on the underlying hash function's collision resistance: The construction's security relies on H's resistance to collision-finding under these cond
      ours: hash-function-substitution — verdict: ? — test: — commit: — perf: —
- [ ] V-0779 S-2104-6-2 (RFC 2104) A hash lacking assumed properties would be unsuitable generally: Implicit: choose only hash functions meeting the commonly assumed cryptographic properties
      ours: hash-function-substitution — verdict: ? — test: — commit: — perf: —
- [ ] V-0780 S-2104-6-3 (RFC 2104) HMAC construction is hash-agnostic and MAC breaks are non-catastrophic to past data: The construction is independent of the specific hash function's internals, allowing replac
      ours: design-overview — verdict: ? — test: — commit: — perf: —
- [ ] V-0781 S-2104-6-4 (RFC 2104) Birthday-bound forgery attack on HMAC: This attack is deemed computationally infeasible for realistic scenarios given typical has
      ours: hash-function-substitution — verdict: ? — test: — commit: — perf: —
- [ ] V-0782 S-2104-6-5 (RFC 2104) Overall system security requires more than just the HMAC construction: A correct implementation of the HMAC construction, the choice of random or cryptographical
      ours: key-management — verdict: ? — test: — commit: — perf: —

## Public-key signatures and key agreement

- [ ] V-0644 CVE-2024-2881 (wolfssl) timing-side-channel: Fault injection vulnerability in EdDSA (Ed25519) signature operations.
      ours: src/crypto/asymmetric/ed25519 — verdict: ? — test: — commit: — perf: —
- [ ] V-0645 CVE-2024-1545 (wolfssl) timing-side-channel: Fault injection vulnerability in RsaPrivateDecryption (RSA private-key operation).
      ours: src/crypto/asymmetric/rsa — verdict: ? — test: — commit: — perf: —
- [ ] V-0646 CVE-2024-1544 (wolfssl) timing-side-channel: ECDSA nonce side channel via biased modular reduction.
      ours: src/crypto/asymmetric/ecdsa (RFC 6979 nonce / modular reduction) — verdict: ? — test: — commit: — perf: —
- [ ] V-0647 CVE-2023-6935 (wolfssl) timing-side-channel: RSA timing vulnerability related to the Marvin attack (PKCS#1 v1.5 padding oracle timing).
      ours: src/crypto/asymmetric/rsa (PKCS#1 v1.5 unpad) — verdict: ? — test: — commit: — perf: —
- [ ] V-0648 CVE-2022-42961 (wolfssl) timing-side-channel: Fault injection via Rowhammer discloses ECDSA private keys.
      ours: src/crypto/asymmetric/ecdsa — verdict: ? — test: — commit: — perf: —
- [ ] V-0649 CVE-2020-36177 (wolfssl) der-length-overflow: RsaPad_PSS out-of-bounds write during RSA-PSS padding.
      ours: src/crypto/asymmetric/rsa (PSS padding) — verdict: ? — test: — commit: — perf: —
- [ ] V-0650 CVE-2020-15309 (wolfssl) timing-side-channel: Cache timing attack on public key operations (RSA/ECDSA).
      ours: src/crypto/asymmetric (RSA/ECDSA private-key ops) — verdict: ? — test: — commit: — perf: —
- [ ] V-0651 CVE-2020-11713 (wolfssl) timing-side-channel: ECC mulmod timing side-channel attack leaks scalar bits.
      ours: src/crypto/asymmetric/ecdsa (scalar mult / modmul) — verdict: ? — test: — commit: — perf: —
- [ ] V-0652 CVE-2020-11735 (wolfssl) timing-side-channel: Non-constant-time modular inverse in fast math library leaks key bits.
      ours: src/crypto/asymmetric (bignum modular inverse) — verdict: ? — test: — commit: — perf: —
- [ ] V-0653 CVE-2020-12966 (wolfssl) timing-side-channel: ECDSA side channel leaks private key on AMD processors.
      ours: src/crypto/asymmetric/ecdsa — verdict: ? — test: — commit: — perf: —
- [ ] V-0654 CVE-2021-46744 (wolfssl) timing-side-channel: ECDSA side channel leaks private key on AMD processors (related to CVE-2020-12966).
      ours: src/crypto/asymmetric/ecdsa — verdict: ? — test: — commit: — perf: —
- [ ] V-0655 CVE-2019-14317 (wolfssl) timing-side-channel: DSA private key recovery timing attack (adjacent asymmetric-signature timing bug class).
      ours: src/crypto/asymmetric (out of our DSA scope, kept for pattern) — verdict: ? — test: — commit: — perf: —
- [ ] V-0656 CVE-2019-13628 (wolfssl) timing-side-channel: ECDSA nonce size leak in signing operations.
      ours: src/crypto/asymmetric/ecdsa (RFC 6979 nonce generation) — verdict: ? — test: — commit: — perf: —
- [ ] V-0657 CVE-2018-16870 (wolfssl) timing-side-channel: Bleichenbacher downgrade attack variant against RSA PKCS#1 v1.5 padding.
      ours: src/crypto/asymmetric/rsa (PKCS#1 v1.5 unpad) — verdict: ? — test: — commit: — perf: —
- [ ] V-0658 CVE-2018-12436 (wolfssl) timing-side-channel: Key extraction side channel attack against ECC private key operations.
      ours: src/crypto/asymmetric/ecdsa — verdict: ? — test: — commit: — perf: —
- [ ] V-0659 CVE-2026-50583 (mbedtls) der-length-overflow: Out-of-bounds read when parsing a zero-length ECC public key.
      ours: src/crypto/asymmetric/ecdsa or x25519 (public key point parse) — verdict: ? — test: — commit: — perf: —
- [ ] V-0660 CVE-2026-50587 (mbedtls) timing-side-channel: Timing side-channel in RSA PKCS#1 v1.5 decryption.
      ours: src/crypto/asymmetric/rsa (PKCS#1v1.5 unpad) — verdict: ? — test: — commit: — perf: —
- [ ] V-0661 CVE-2026-35336 (mbedtls) der-length-overflow: Possible buffer overflow in mbedtls_ecdh_calc_secret() (X25519/ECDH shared secret computation).
      ours: src/crypto/asymmetric/x25519 (shared secret calc) — verdict: ? — test: — commit: — perf: —
- [ ] V-0662 CVE-2026-54434 (mbedtls) low-order-point: Everest (X25519) implementation lacks contributory behaviour due to improper input validation (low-order point
      ours: src/crypto/asymmetric/x25519 (contributory behavior check) — verdict: ? — test: — commit: — perf: —
- [ ] V-0663 CVE-2026-54435 (mbedtls) timing-side-channel: Side channel leak in ECC optimized modp reduction.
      ours: src/crypto/asymmetric/ecdsa (modp reduction) — verdict: ? — test: — commit: — perf: —
- [ ] V-0664 CVE-2025-66442 (mbedtls) timing-side-channel: Compiler-induced constant-time violations break constant-time crypto guarantees.
      ours: src/crypto/* (constant-time primitive helpers, compiler optimization risk) — verdict: ? — test: — commit: — perf: —
- [ ] V-0665 CVE-2025-54764 (mbedtls) timing-side-channel: Side channel in RSA key generation and operations (SSBleed/M-Step class).
      ours: src/crypto/asymmetric/rsa (keygen and private ops) — verdict: ? — test: — commit: — perf: —
- [ ] V-0666 N-2024-08-ecdsaconvoverflow (mbedtls) der-length-overflow: Stack buffer overflow in ECDSA signature conversion functions (ASN.1<->raw r,s conversion).
      ours: src/crypto/asymmetric/ecdsa (signature DER<->raw conversion) — verdict: ? — test: — commit: — perf: —
- [ ] V-0667 N-2024-01-rsatiming (mbedtls) timing-side-channel: Timing side channel in private key RSA operations.
      ours: src/crypto/asymmetric/rsa — verdict: ? — test: — commit: — perf: —
- [ ] V-0668 N-2021-07-montgomery (mbedtls) timing-side-channel: Local side channel attack on static Diffie-Hellman with Montgomery curves (X25519/X448).
      ours: src/crypto/asymmetric/x25519 — verdict: ? — test: — commit: — perf: —
- [ ] V-0669 N-2021-07-rsaside (mbedtls) timing-side-channel: Local side channel attack on RSA.
      ours: src/crypto/asymmetric/rsa — verdict: ? — test: — commit: — perf: —
- [ ] V-0670 N-2020-09-rsadhside (mbedtls) timing-side-channel: Local side channel attack on RSA and static Diffie-Hellman.
      ours: src/crypto/asymmetric/rsa — verdict: ? — test: — commit: — perf: —
- [ ] V-0671 N-2020-07-eccimport (mbedtls) timing-side-channel: Side-channel attack on ECC key import and validation.
      ours: src/crypto/asymmetric/ecdsa or x25519 (key import validation) — verdict: ? — test: — commit: — perf: —
- [ ] V-0672 N-2020-04-ecdsaside (mbedtls) timing-side-channel: Side channel attack on ECDSA signing leaking nonce/key bits.
      ours: src/crypto/asymmetric/ecdsa — verdict: ? — test: — commit: — perf: —
- [ ] V-0673 N-2019-12-ecdsaside2 (mbedtls) timing-side-channel: Side channel attack on ECDSA.
      ours: src/crypto/asymmetric/ecdsa — verdict: ? — test: — commit: — perf: —
- [ ] V-0674 N-2019-10-detecdsaside (mbedtls) timing-side-channel: Side channel attack on deterministic ECDSA (RFC 6979 nonce).
      ours: src/crypto/asymmetric/ecdsa (RFC 6979 nonce generation) — verdict: ? — test: — commit: — perf: —
- [ ] V-0675 CVE-2024-28834 (gnutls) timing-side-channel: Timing side-channel in deterministic ECDSA leaking bit-length of the random nonce, enabling private key recove
      ours: src/crypto/asymmetric/ecdsa (RFC 6979 nonce) — verdict: ? — test: — commit: — perf: —
- [ ] V-0676 CVE-2023-0361 (gnutls) timing-side-channel: Timing side-channel in RSA decryption: response time differences between malformed and valid PKCS#1 v1.5 padde
      ours: src/crypto/asymmetric/rsa (PKCS#1v1.5 unpad) — verdict: ? — test: — commit: — perf: —
- [ ] V-0677 CVE-2018-12440 (boringssl) timing-side-channel: Memory-cache side-channel attack on DSA signatures (ROHNP, Return Of the Hidden Number Problem).
      ours: src/crypto/asymmetric (DSA not in our scope; nonce/timing pattern relevant to ECDSA/RSA) — verdict: ? — test: — commit: — perf: —
- [ ] V-0678 CVE-2018-12434 (libressl) timing-side-channel: Memory-cache side-channel attack on DSA and ECDSA signatures (ROHNP).
      ours: src/crypto/asymmetric/ecdsa — verdict: ? — test: — commit: — perf: —
- [ ] V-0679 N-nss-2023-53 (nss) timing-side-channel: Timing side-channel in PKCS#1 v1.5 decryption depadding code.
      ours: src/crypto/asymmetric/rsa (PKCS#1v1.5 unpad) — verdict: ? — test: — commit: — perf: —
- [ ] V-0680 N-nss-2021-51 (nss) der-length-overflow: Memory corruption in NSS via DER-encoded DSA and RSA-PSS signatures.
      ours: src/crypto/asymmetric/rsa (PSS signature DER decode) — verdict: ? — test: — commit: — perf: —
- [ ] V-0681 CVE-2025-69277 (libsodium) invalid-curve: crypto_core_ed25519_is_valid_point() incompletely validates Ed25519 points: only checked X-coordinate after co
      ours: src/crypto/asymmetric/ed25519 (point validation / subgroup check) — verdict: ? — test: — commit: — perf: —
- [ ] V-0682 CVE-2024-34703 (botan) der-length-overflow: DoS due to oversized elliptic curve parameters: ASN.1 ECC decoding lacked maximum size validation on prime par
      ours: src/crypto/asymmetric/ecdsa (ASN.1 curve parameter decode) — verdict: ? — test: — commit: — perf: —
- [ ] V-0683 N-botan-oaep-timing (botan) timing-side-channel: RSA decryption with certain OAEP padding options had a detectable timing channel usable to recover plaintext.
      ours: src/crypto/asymmetric/rsa (OAEP unpad; PSS verify shares padding-check patterns) — verdict: ? — test: — commit: — perf: —
- [ ] V-0684 CVE-2018-20187 (botan) timing-side-channel: Timing side channel during ECC key generation could leak information about the high bits of the secret scalar.
      ours: src/crypto/asymmetric/ecdsa (or x25519) keygen — verdict: ? — test: — commit: — perf: —
- [ ] V-0685 CVE-2018-12435 (botan) timing-side-channel: Side channel in ECDSA signature operations enabling secret key recovery by a local attacker.
      ours: src/crypto/asymmetric/ecdsa — verdict: ? — test: — commit: — perf: —
- [ ] V-0686 CVE-2018-1000180 (bc-java) signature-malleability: ECDSA does not fully validate ASN.1 encoding of signatures, allowing injection of extra elements that still va
      ours: src/crypto/asymmetric/ecdsa (signature DER decode/validation) — verdict: ? — test: — commit: — perf: —
- [ ] V-0687 N-bc-dsa-timing-1.55 (bc-java) timing-side-channel: DSA signature generation vulnerable to timing attacks due to lack of blinding (v1.55 and earlier).
      ours: src/crypto/asymmetric (DSA out of scope; nonce-blinding pattern relevant to ECDSA) — verdict: ? — test: — commit: — perf: —
- [ ] V-0688 CVE-2020-15522 (bc-java) timing-side-channel: Timing issue in the EC math library exposes private key information for deterministic ECDSA signatures.
      ours: src/crypto/asymmetric/ecdsa (RFC 6979 deterministic nonce, EC scalar math) — verdict: ? — test: — commit: — perf: —
- [ ] V-0689 CVE-2024-30171 (bc-java) timing-side-channel: Timing side-channel in RSA decryption (both PKCS#1 v1.5 and OAEP) allows an authenticated attacker to obtain s
      ours: src/crypto/asymmetric/rsa — verdict: ? — test: — commit: — perf: —
- [ ] V-0690 CVE-2024-30172 (bc-java) signature-malleability: Infinite loop in Ed25519 verification code triggered by a specially crafted signature and public key, causing 
      ours: src/crypto/asymmetric/ed25519 (signature verify loop/termination) — verdict: ? — test: — commit: — perf: —
- [ ] V-0691 CVE-2024-29857 (bc-java) der-length-overflow: Excessive CPU consumption when importing EC certificates with crafted F2m (binary field) curve parameters.
      ours: src/crypto/asymmetric/ecdsa (curve parameter import validation) — verdict: ? — test: — commit: — perf: —
- [ ] V-0692 CVE-2019-6486 (go-crypto-elliptic) modexp-bug: DoS vulnerability in crypto/elliptic P-521 and P-384 implementations may let an attacker craft inputs consumin
      ours: src/crypto/asymmetric/ecdsa (P-384 scalar mult) — verdict: ? — test: — commit: — perf: —
- [ ] V-0693 CVE-2022-21449 (java-se (jdk 15-18 ECDSA)) signature-malleability: Psychic Signatures: Java's rewritten (pure-Java, from native) ECDSA verification failed to check that signatur
      ours: src/crypto/asymmetric/ecdsa (signature verify: must reject r==0 or s==0 before doing the verification equation) — verdict: ? — test: — commit: — perf: —
- [ ] V-0694 CVE-2023-4421 (pyca/cryptography) timing-side-channel: A prior mitigation for Bleichenbacher-style attacks on RSA PKCS#1 v1.5 decryption was found ineffective (Marvi
      ours: src/crypto/asymmetric/rsa (PKCS#1v1.5 unpad, constant-time requirement) — verdict: ? — test: — commit: — perf: —
- [ ] V-0695 CVE-2023-6237 (openssl) timing-side-channel: Excessive time spent checking DSA/RSA public keys and parameters (including RSA public keys with an excessivel
      ours: src/crypto/asymmetric/rsa (public key validation bounds/time) — verdict: ? — test: — commit: — perf: —
- [ ] V-0696 CVE-2023-49092 (rsa (Rust crate)) timing-side-channel: Non-constant-time RSA PKCS#1v1.5 implementation in the RustCrypto rsa crate leaks private-key information via 
      ours: src/crypto/asymmetric/rsa (PKCS#1v1.5 decrypt/unpad) — verdict: ? — test: — commit: — perf: —
- [ ] V-0697 L-minerva-ecdsa-timing (python-ecdsa, jsrsasign, various smartcards) timing-side-channel: Minerva: ECDSA/EC-Schnorr nonce-length timing side channel in scalar multiplication lets an attacker recover p
      ours: src/crypto/asymmetric/ecdsa (RFC 6979 nonce generation and scalar multiplication must be constant-time in nonce bit-length) — verdict: ? — test: — commit: — perf: —
- [ ] V-0698 L-ed25519-malleability (EdDSA implementations (general)) signature-malleability: Ed25519 signatures are malleable unless the verifier checks that the decoded S scalar is strictly less than th
      ours: src/crypto/asymmetric/ed25519 (signature verify: must reject S >= L before/along with the verification equation) — verdict: ? — test: — commit: — perf: —
- [ ] V-0699 L-ed25519-double-pubkey-oracle (ed25519-dalek (<2.0)) signature-malleability: Double Public Key Signing Function Oracle Attack: an EdDSA API that accepts a serialized 64-byte keypair (32-b
      ours: src/crypto/asymmetric/ed25519 (signing API surface: must derive the public key internally from the seed, never accept caller-supplied public key alongside a private scalar for signing) — verdict: ? — test: — commit: — perf: —
- [ ] V-0700 L-invalid-curve-ecdh (ECDH implementations generally (TLS-ECDH)) invalid-curve: Invalid curve / small-subgroup-confinement attacks: sending a peer an ECDH public point that lies on a differe
      ours: src/crypto/asymmetric/x25519 and ecdsa (peer public-key/point validation before scalar multiplication) — verdict: ? — test: — commit: — perf: —
- [ ] V-0701 CVE-2026-26007 (pyca/cryptography (SECT binary curves)) invalid-curve: Subgroup confinement attack: missing subgroup validation for SECT (binary field) curves in pyca/cryptography a
      ours: src/crypto/asymmetric/ecdsa (P-256/P-384 have cofactor 1 so this exact CVE doesn't apply, but confirms point-on-curve + subgroup-order validation must be checked, not assumed from cofactor) — verdict: ? — test: — commit: — perf: —
- [ ] V-0702 CVE-2018-0734 (openssl) timing-side-channel: Timing side channel in DSA signature generation (out of our primitive scope, DSA not implemented, kept as patt
      ours: not applicable: DSA not in our primitive list — verdict: ? — test: — commit: — perf: —
- [ ] V-0703 CVE-2018-0735 (openssl) timing-side-channel: Timing side channel attack in ECDSA signature generation could allow recovery of the private key.
      ours: src/crypto/asymmetric/ecdsa (scalar multiplication / nonce handling in sign) — verdict: ? — test: — commit: — perf: —
- [ ] V-0704 CVE-2019-1547 (openssl) timing-side-channel: EC_GROUP built from explicit (not named-curve) parameters can lack the cofactor value, causing OpenSSL to fall
      ours: src/crypto/asymmetric/ecdsa (curve parameter handling must not silently disable constant-time path; our SDK only supports named P-256/P-384 so explicit-parameter confusion should be structurally impossible -- worth a regression test asserting only named curves are ever accepted) — verdict: ? — test: — commit: — perf: —
- [ ] V-0705 CVE-2019-1551 (openssl) carry-propagation-bug: Integer overflow in the x86_64 Montgomery squaring procedure used in modular exponentiation with 512-bit modul
      ours: src/crypto/asymmetric (bignum/modular exponentiation carry handling in Montgomery multiplication) — verdict: ? — test: — commit: — perf: —
- [ ] V-0706 CVE-2021-4160 (openssl) carry-propagation-bug: Carry propagation bug in the MIPS32/MIPS64 squaring procedure (bn_sqr) used by multiple EC algorithms and some
      ours: src/crypto/asymmetric (bignum squaring/modexp carry propagation; architecture-specific bug but the CLASS -- squaring routines must be exhaustively tested for carry correctness across all limb-boundary cases -- applies to our own bignum implementation regardless of target arch) — verdict: ? — test: — commit: — perf: —
- [ ] V-0707 CVE-2022-2274 (openssl) modexp-bug: RSA implementation for AVX512IFMA-capable x86_64 CPUs (OpenSSL 3.0.4 only) produced incorrect computation resu
      ours: src/crypto/asymmetric/rsa (modular exponentiation, CPU-feature-specific fast path correctness) — verdict: ? — test: — commit: — perf: —
- [ ] V-0708 CVE-2024-13176 (openssl) timing-side-channel: Timing side-channel in ECDSA signature computation, most measurable on NIST P-521 (roughly 300ns of timing var
      ours: src/crypto/asymmetric/ecdsa (P-384 scalar operations should be checked against the same class of leakage OpenSSL found on P-521) — verdict: ? — test: — commit: — perf: —
- [ ] V-0709 CVE-2018-0737 (openssl) timing-side-channel: Cache timing side-channel vulnerability in RSA key generation, potentially allowing recovery of private key ma
      ours: src/crypto/asymmetric/rsa (key generation, prime candidate sieving/testing) — verdict: ? — test: — commit: — perf: —
- [ ] V-0710 CVE-2018-5407 (openssl (PortSmash / SMT side channel)) timing-side-channel: Microarchitecture (port-contention, 'PortSmash') timing side channel in ECC scalar multiplication used by ECDS
      ours: src/crypto/asymmetric/ecdsa and x25519 (scalar multiplication constant-time/constant-port-usage requirement) — verdict: ? — test: — commit: — perf: —
- [ ] V-0711 L-0028 (Marvin Attack: timing side-cha) timing-side-channel: 
      ours: timing-side-channel — verdict: ? — test: — commit: — perf: —
- [ ] V-0712 L-0029 (Minerva: ECDSA/EdDSA nonce-len) timing-side-channel: 
      ours: timing-side-channel — verdict: ? — test: — commit: — perf: —
- [ ] V-0713 L-0030 (Psychic Signatures: ECDSA veri) signature-verification-bypass: 
      ours: signature-verification-bypass — verdict: ? — test: — commit: — perf: —
- [ ] V-0714 L-0031 (Taming the many EdDSAs: Ed2551) signature-malleability: 
      ours: signature-malleability — verdict: ? — test: — commit: — perf: —
- [ ] V-0715 L-0032 (Double Public Key Signing Func) signing-oracle-key-recovery: 
      ours: signing-oracle-key-recovery — verdict: ? — test: — commit: — perf: —
- [ ] V-0716 L-0033 (X25519 non-contributory / low-) non-contributory-dh: 
      ours: non-contributory-dh — verdict: ? — test: — commit: — perf: —
- [ ] V-0717 S-7748-7-1 (RFC 7748) Curve25519 security level below the nominal 128-bit round number: Curve25519's security level is slightly under the standard 128-bit level but remains accep
      ours: curve-strength-misjudgment — verdict: ? — test: — commit: — perf: —
- [ ] V-0718 S-7748-7-2 (RFC 7748) Curve448 as a paranoia/performance trade-off: Curve448's ~224-bit security is a trade-off between performance and paranoia; reasonable p
      ours: curve-strength-misjudgment — verdict: ? — test: — commit: — perf: —
- [ ] V-0719 S-7748-7-3 (RFC 7748) Low-order point / non-contributory input attack: Protocol designers must not assume contributory behaviour; implementations MAY check for a
      ours: low-order-point — verdict: ? — test: — commit: — perf: —
- [ ] V-0720 S-7748-7-4 (RFC 7748) Public key equivalence class as an identifier-confusion risk: Designers should recognize this equivalence and include the public key material in key der
      ours: key-confusion — verdict: ? — test: — commit: — perf: —
- [ ] V-0721 S-7748-7-5 (RFC 7748) Non-canonical input handling differs across implementations (fingerprinting/interop risk): Implementations using generic elliptic-curve libraries instead of the specified Montgomery
      ours: invalid-curve — verdict: ? — test: — commit: — perf: —
- [ ] V-0722 S-8032-8.1-1 (RFC 8032) Timing side-channel leakage of the private key: The implementation must execute exactly the same sequence of instructions and perform exac
      ours: timing-side-channel — verdict: ? — test: — commit: — perf: —
- [ ] V-0723 S-8032-8.1-2 (RFC 8032) Data-dependent branches in modular arithmetic and scalar multiplication: Modulo p arithmetic must avoid data-dependent branches related to carry propagation; point
      ours: timing-side-channel — verdict: ? — test: — commit: — perf: —
- [ ] V-0724 S-8032-8.1-3 (RFC 8032) Complete addition formulas ease side-channel-silent implementation: The complete addition formulas used by these curves make side-channel-silent implementatio
      ours: timing-side-channel — verdict: ? — test: — commit: — perf: —
- [ ] V-0725 S-8032-8.1-4 (RFC 8032) Reference implementation explicitly not side-channel silent: The document explicitly notes that its example implementations do not attempt to be side-c
      ours: timing-side-channel — verdict: ? — test: — commit: — perf: —
- [ ] V-0726 S-8032-8.2-1 (RFC 8032) Deterministic signatures avoid poor-randomness attacks at signing time: EdDSA signatures are deterministic, which protects against attacks stemming from poor rand
      ours: nonce-reuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0727 S-8032-8.2-2 (RFC 8032) Private key generation still requires good randomness: Private key generation requires randomness, though because the private key is hashed befor
      ours: weak-randomness — verdict: ? — test: — commit: — perf: —
- [ ] V-0728 S-8032-8.2-3 (RFC 8032) Batch verification may reintroduce a randomness dependency: Basic signature verification is deterministic, but batch verification optimizations may re
      ours: weak-randomness — verdict: ? — test: — commit: — perf: —
- [ ] V-0729 S-8032-8.3-1 (RFC 8032) Context misuse causing cross-protocol signature confusion: The context SHOULD be a constant string specified by the protocol, SHOULD NOT incorporate 
      ours: signature-malleability — verdict: ? — test: — commit: — perf: —
- [ ] V-0730 S-8032-8.3-2 (RFC 8032) Context support inconsistency across implementations/APIs: Implementers are warned that contexts create API complexity and may not be available in al
      ours: signature-malleability — verdict: ? — test: — commit: — perf: —
- [ ] V-0731 S-8032-8.4-1 (RFC 8032) Signature malleability via unreduced S value: Verification MUST check that the decoded S value is smaller than the group order L; Ed2551
      ours: signature-malleability — verdict: ? — test: — commit: — perf: —
- [ ] V-0732 S-8032-8.5-1 (RFC 8032) Security-level choice between Ed25519 (128-bit) and Ed448 (224-bit): Ed25519/Ed25519ph provide 128-bit strength and Ed448/Ed448ph provide 224-bit strength; if 
      ours: curve-strength-misjudgment — verdict: ? — test: — commit: — perf: —
- [ ] V-0733 S-8032-8.5-2 (RFC 8032) Prehashed variants add hash-function attack surface for little benefit: These prehashed variants SHOULD NOT be used except for legacy API interoperability, since 
      ours: hash-function-substitution — verdict: ? — test: — commit: — perf: —
- [ ] V-0734 S-8032-8.5-3 (RFC 8032) Summary recommendation restated: In summary, if a 128-bit security level is enough, use of Ed25519 is RECOMMENDED; otherwis
      ours: curve-strength-misjudgment — verdict: ? — test: — commit: — perf: —
- [ ] V-0735 S-8032-8.6-1 (RFC 8032) Cross-variant signature confusion is infeasible, permitting key reuse: The schemes resist mixing prehashes — finding such a cross-variant-verifying message is in
      ours: signature-malleability — verdict: ? — test: — commit: — perf: —
- [ ] V-0736 S-8032-8.7-1 (RFC 8032) Streaming (Initialize-Update-Finalize) verification interfaces risk processing unverified data: Implementers should avoid signing or verifying large amounts of data via streaming interfa
      ours: unverified-data-processing — verdict: ? — test: — commit: — perf: —
- [ ] V-0737 S-8032-8.7-2 (RFC 8032) Explicit warning against IUF verification APIs: The specification explicitly warns against such interfaces, given that any error in them w
      ours: unverified-data-processing — verdict: ? — test: — commit: — perf: —
- [ ] V-0738 S-8032-8.8-1 (RFC 8032) Cofactor multiplication in verification prevents implementation-disagreement fingerprinting: Verification formulas multiply points by the cofactor; while not strictly necessary for se
      ours: signature-malleability — verdict: ? — test: — commit: — perf: —
- [ ] V-0739 S-8017-7.2-1 (RFC 8017) Bleichenbacher chosen-ciphertext attack on RSAES-PKCS1-v1_5: If RSAES-PKCS1-v1_5 is to be used, countermeasures should be taken: adding structure to th
      ours: padding-oracle — verdict: ? — test: — commit: — perf: —
- [ ] V-0740 S-8017-7.2-2 (RFC 8017) Low-exponent attacks on long messages: Care should be taken to avoid these low-exponent attacks, e.g. by bounding message length 
      ours: low-exponent-attack — verdict: ? — test: — commit: — perf: —
- [ ] V-0741 S-8017-7.2-3 (RFC 8017) RSAES-PKCS1-v1_5 not recommended for arbitrary message encryption: As a general rule, use of this scheme for encrypting an arbitrary message, as opposed to a
      ours: padding-oracle — verdict: ? — test: — commit: — perf: —
- [ ] V-0742 S-8017-8.1-1 (RFC 8017) RSASSA-PSS forgery reduces to inverting RSA under random-oracle assumptions: RSASSA-PSS provides secure signatures such that the difficulty of forging signatures can b
      ours: signature-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0743 S-8017-8.1-2 (RFC 8017) Hash function substitution risk in the mask generation function: It is RECOMMENDED that the EMSA-PSS mask generation function be based on the same hash fun
      ours: hash-function-substitution — verdict: ? — test: — commit: — perf: —
- [ ] V-0744 S-8017-8.2-1 (RFC 8017) RSASSA-PKCS1-v1_5 has no known attacks but weaker security proof than PSS: In the interest of increased robustness, RSASSA-PSS is REQUIRED in new applications.
      ours: signature-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0745 S-8017-8.2-2 (RFC 8017) Recommended transition path away from PKCS1-v1_5 signatures: A gradual transition to EMSA-PSS is recommended as a precaution against future development
      ours: signature-forgery — verdict: ? — test: — commit: — perf: —
- [ ] V-0746 S-6979-4-1 (RFC 6979) Private key handling remains out of scope but critical: Private key generation, storage, access control, and disposal are sensitive operations tha
      ours: key-management — verdict: ? — test: — commit: — perf: —
- [ ] V-0747 S-6979-4-2 (RFC 6979) Private key generation still absolutely requires strong randomness: Private key generation absolutely requires a strongly random source; the specification ass
      ours: weak-randomness — verdict: ? — test: — commit: — perf: —
- [ ] V-0748 S-6979-4-3 (RFC 6979) Determinism eliminates hard-to-test randomized-nonce failure modes: Deterministic signatures enhance security by enabling testing against fixed test vectors a
      ours: nonce-reuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0749 S-6979-4-4 (RFC 6979) Security relies on HMAC_DRBG behaving as a pseudorandom oracle: The construction relies on HMAC_DRBG functioning as a pseudorandom oracle; security depend
      ours: nonce-reuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0750 S-6979-4-5 (RFC 6979) Deterministic nonce derivation as a side-channel target: The determinism of the algorithms described in this note may be useful to an attacker in s
      ours: timing-side-channel — verdict: ? — test: — commit: — perf: —
- [ ] V-0751 S-6979-4-6 (RFC 6979) Private key used both for signing and as HMAC_DRBG input requires HMAC to remain secure under key exposure conditions: The scheme requires HMAC to remain a random oracle/secure PRF even in this dual-use config
      ours: nonce-reuse — verdict: ? — test: — commit: — perf: —

## X.509 / DER / PKI

- [ ] V-0513 CVE-2026-11310 (wolfssl) name-constraint-bypass: X.509 trust-chain bypass in the OpenSSL compatibility certificate verifier.
      ours: src/crypto/pki (path validation, cert chain build) — verdict: ? — test: — commit: — perf: —
- [ ] V-0514 CVE-2026-11999 (wolfssl) ca-bit: X.509 trust-chain bypass via path-depth exhaustion affecting certificate path building.
      ours: src/crypto/pki (chain depth / pathlen checks) — verdict: ? — test: — commit: — perf: —
- [ ] V-0515 CVE-2026-55960 (wolfssl) name-constraint-bypass: Un-negotiated Raw Public Key accepted, bypassing chain validation.
      ours: src/tls (RPK extension) + src/crypto/pki — verdict: ? — test: — commit: — perf: —
- [ ] V-0516 CVE-2026-6731 (wolfssl) name-constraint-bypass: X.509 name constraint bypass via Subject Common Name.
      ours: src/crypto/pki (name constraints, SAN/CN matching) — verdict: ? — test: — commit: — perf: —
- [ ] V-0517 CVE-2026-10592 (wolfssl) name-constraint-bypass: Wildcard DNS SANs bypass CA name-constraint checks.
      ours: src/crypto/pki (name constraints, wildcard hostname matching) — verdict: ? — test: — commit: — perf: —
- [ ] V-0518 CVE-2026-7532 (wolfssl) name-constraint-bypass: iPAddress name constraints bypass in certificate chain validation.
      ours: src/crypto/pki (name constraints, iPAddress SAN) — verdict: ? — test: — commit: — perf: —
- [ ] V-0519 CVE-2026-6091 (wolfssl) name-constraint-bypass: Partial-chain certificate verification accepts untrusted intermediates.
      ours: src/crypto/pki (chain building/trust anchor) — verdict: ? — test: — commit: — perf: —
- [ ] V-0520 CVE-2026-5501 (wolfssl) name-constraint-bypass: X509_verify_cert accepts chain without leaf signature verification.
      ours: src/crypto/pki (leaf signature check step) — verdict: ? — test: — commit: — perf: —
- [ ] V-0521 CVE-2026-5447 (wolfssl) der-length-overflow: Heap buffer overflow in CertFromX509 via AuthorityKeyIdentifier extension.
      ours: src/crypto/pki (DER extension parsing, AKI) — verdict: ? — test: — commit: — perf: —
- [ ] V-0522 CVE-2026-5263 (wolfssl) name-constraint-bypass: URI nameConstraints not enforced during chain verification.
      ours: src/crypto/pki (name constraints, URI SAN) — verdict: ? — test: — commit: — perf: —
- [ ] V-0523 CVE-2026-5187 (wolfssl) der-length-overflow: Heap OOB write in DecodeObjectId via off-by-one check.
      ours: src/crypto/pki (ASN.1 OID decode) — verdict: ? — test: — commit: — perf: —
- [ ] V-0524 CVE-2026-5188 (wolfssl) der-length-overflow: Integer underflow in SAN extension parsing causes length wrap.
      ours: src/crypto/pki (SAN/GENERAL_NAME parsing) — verdict: ? — test: — commit: — perf: —
- [ ] V-0525 CVE-2026-5772 (wolfssl) hostname-mismatch: Stack over-read in wildcard pattern matching for hostname verification.
      ours: src/crypto/pki (hostname/wildcard matching) — verdict: ? — test: — commit: — perf: —
- [ ] V-0526 CVE-2026-5392 (wolfssl) der-length-overflow: Heap out-of-bounds read in PKCS7 parsing (adjacent ASN.1 decode path).
      ours: src/crypto/pki (shared ASN.1 length decode) — verdict: ? — test: — commit: — perf: —
- [ ] V-0527 CVE-2026-6412 (wolfssl) non-canonical-encoding: Continued acceptance of SHA-1/MD5 in certificate signature processing.
      ours: src/crypto/pki (signature algorithm policy) — verdict: ? — test: — commit: — perf: —
- [ ] V-0528 CVE-2026-6450 (wolfssl) name-constraint-bypass: CRL critical extension bypass.
      ours: src/crypto/pki (CRL/extension criticality handling) — verdict: ? — test: — commit: — perf: —
- [ ] V-0529 CVE-2025-7395 (wolfssl) name-constraint-bypass: Native certificate validation overrides other verification errors, potentially masking failures.
      ours: src/crypto/pki (verification result aggregation) — verdict: ? — test: — commit: — perf: —
- [ ] V-0530 CVE-2024-5991 (wolfssl) hostname-mismatch: MatchDomainName reads beyond non-null-terminated string bounds during hostname matching.
      ours: src/crypto/pki (hostname/SAN matching) — verdict: ? — test: — commit: — perf: —
- [ ] V-0531 CVE-2021-38597 (wolfssl) name-constraint-bypass: OCSP verification bypassed by NoCheck extension in certificate chain validation.
      ours: src/crypto/pki (revocation/extension handling) — verdict: ? — test: — commit: — perf: —
- [ ] V-0532 CVE-2021-24116 (wolfssl) timing-side-channel: Base64 PEM decoding side-channel timing leak.
      ours: src/crypto/pki (PEM decode) — verdict: ? — test: — commit: — perf: —
- [ ] V-0533 CVE-2019-18840 (wolfssl) der-length-overflow: Heap buffer overflow in ASN.1 certificate parsing.
      ours: src/crypto/pki (ASN.1/DER cert decode) — verdict: ? — test: — commit: — perf: —
- [ ] V-0534 CVE-2019-16748 (wolfssl) der-length-overflow: Heap buffer over-read in CheckCertSignature_ex during certificate signature verification.
      ours: src/crypto/pki (cert signature verification) — verdict: ? — test: — commit: — perf: —
- [ ] V-0535 CVE-2019-15651 (wolfssl) der-length-overflow: Heap buffer over-read in DecodeCertExtensions during X.509 extension parsing.
      ours: src/crypto/pki (X.509 extension decode) — verdict: ? — test: — commit: — perf: —
- [ ] V-0536 CVE-2026-49300 (mbedtls) ca-bit: X.509 CA bit forgery via invalid basicConstraints extension encoding.
      ours: src/crypto/pki (basicConstraints parsing) — verdict: ? — test: — commit: — perf: —
- [ ] V-0537 CVE-2026-54441 (mbedtls) non-canonical-encoding: Signature algorithm restrictions not enforced on certificate chain, allowing weak algorithms.
      ours: src/crypto/pki (signature algorithm policy in chain validation) — verdict: ? — test: — commit: — perf: —
- [ ] V-0538 CVE-2026-25834 (mbedtls) name-constraint-bypass: Signature Algorithm Injection allows attacker to inject signature algorithms during certificate processing.
      ours: src/crypto/pki (signature algorithm identifier parsing) — verdict: ? — test: — commit: — perf: —
- [ ] V-0539 CVE-2026-34874 (mbedtls) der-length-overflow: Null pointer dereference when setting a distinguished name (malformed X.509 name).
      ours: src/crypto/pki (X.509 name parsing) — verdict: ? — test: — commit: — perf: —
- [ ] V-0540 CVE-2026-25833 (mbedtls) der-length-overflow: Buffer underflow in x509_inet_pton_ipv6() during IPv6 address parsing (SAN iPAddress).
      ours: src/crypto/pki (SAN iPAddress parse) — verdict: ? — test: — commit: — perf: —
- [ ] V-0541 N-2025-06-x509string (mbedtls) der-length-overflow: Misleading memory management in mbedtls_x509_string_to_names() (resource confusion in X.509 name parsing).
      ours: src/crypto/pki (X.509 name string parsing) — verdict: ? — test: — commit: — perf: —
- [ ] V-0542 N-2025-06-asn1namedcrash (mbedtls) der-length-overflow: NULL pointer dereference after using mbedtls_asn1_store_named_data().
      ours: src/crypto/pki (ASN.1 named-data storage) — verdict: ? — test: — commit: — perf: —
- [ ] V-0543 N-2024-01-x509extoverflow (mbedtls) der-length-overflow: Buffer overflow in mbedtls_x509_set_extension() when adding X.509 extensions.
      ours: src/crypto/pki (X.509 extension write path) — verdict: ? — test: — commit: — perf: —
- [ ] V-0544 CVE-2026-42013 (gnutls) hostname-mismatch: Certificate validation flaw: fallback path incorrectly checked DNS hostnames against Common Name field with ov
      ours: src/crypto/pki (hostname matching fallback to CN) — verdict: ? — test: — commit: — perf: —
- [ ] V-0545 CVE-2026-42012 (gnutls) name-constraint-bypass: Certificate misuse: certificates could be used beyond intended purpose via improper validation fallback for UR
      ours: src/crypto/pki (SAN type validation / extended key usage) — verdict: ? — test: — commit: — perf: —
- [ ] V-0546 CVE-2026-42011 (gnutls) name-constraint-bypass: Name constraint bypass: permitted constraints from a prior CA that had only excluded constraints were wrongly 
      ours: src/crypto/pki (name constraints accumulation across chain) — verdict: ? — test: — commit: — perf: —
- [ ] V-0547 CVE-2026-3833 (gnutls) name-constraint-bypass: Case-sensitive domain name comparison violating RFC 5280, causing excluded name constraints to incorrectly acc
      ours: src/crypto/pki (hostname case-folding in name constraints) — verdict: ? — test: — commit: — perf: —
- [ ] V-0548 CVE-2025-14831 (gnutls) name-constraint-bypass: Denial of service via pathological name constraints causing resource exhaustion during certificate validation.
      ours: src/crypto/pki (name constraints evaluation complexity) — verdict: ? — test: — commit: — perf: —
- [ ] V-0549 CVE-2025-32989 (gnutls) der-length-overflow: Heap read buffer overflow with malformed SCT (Signed Certificate Timestamp) extension length in X.509 certific
      ours: src/crypto/pki (SCT/extension length parsing) — verdict: ? — test: — commit: — perf: —
- [ ] V-0550 CVE-2024-12243 (gnutls) name-constraint-bypass: Denial of service via multiple Name Constraints extensions causing excessive validation time.
      ours: src/crypto/pki (name constraints evaluation) — verdict: ? — test: — commit: — perf: —
- [ ] V-0551 CVE-2024-28835 (gnutls) ca-bit: Denial of service with certificate chains exceeding 16 certificates causing an assertion failure.
      ours: src/crypto/pki (chain length limit handling) — verdict: ? — test: — commit: — perf: —
- [ ] V-0552 CVE-2024-0567 (gnutls) ca-bit: Denial of service with cyclic cross-signed certificate chains causing an assertion failure.
      ours: src/crypto/pki (chain building cycle detection) — verdict: ? — test: — commit: — perf: —
- [ ] V-0553 CVE-2019-3829 (gnutls) der-length-overflow: Double-free triggered during certificate verification with malformed certificates.
      ours: src/crypto/pki (certificate verification error path) — verdict: ? — test: — commit: — perf: —
- [ ] V-0554 N-libressl-x509verify-errdiscard (libressl) name-constraint-bypass: x509/x509_verify.c: error for an unverified certificate chain sometimes discarded, causing authentication bypa
      ours: src/crypto/pki (chain verification error propagation) — verdict: ? — test: — commit: — perf: —
- [ ] V-0555 N-libressl-x509verifyctx-leaferr (libressl) name-constraint-bypass: x509_verify_ctx_add_chain does not store errors occurring during leaf certificate verification, returning an i
      ours: src/crypto/pki (leaf verification error tracking) — verdict: ? — test: — commit: — perf: —
- [ ] V-0556 N-libressl-mailbox-overread (libressl) der-length-overflow: x509_constraints_parse_mailbox has a stack-based buffer over-read when input exceeds DOMAIN_PART_MAX_LEN.
      ours: src/crypto/pki (name constraints, rfc822Name/mailbox parsing) — verdict: ? — test: — commit: — perf: —
- [ ] V-0557 GHSA-7v2g-v7wj-26jg (s2n-tls) name-constraint-bypass: OCSP stapling revocation check bypass: malicious server tricks s2n client into accepting a revoked certificate
      ours: src/crypto/pki (revocation checking, OCSP-only path) / src/tls (stapled response handling) — verdict: ? — test: — commit: — perf: —
- [ ] V-0558 CVE-2026-48057 (botan) name-constraint-bypass: X.509 DN decoding lost structural information, allowing nameConstraint bypass.
      ours: src/crypto/pki (DN decode, name constraints) — verdict: ? — test: — commit: — perf: —
- [ ] V-0559 CVE-2026-34580 (botan) name-constraint-bypass: Certificate verification bypass due to trust anchor confusion: end-entity certificates matching a trust anchor
      ours: src/crypto/pki (trust anchor matching / chain building) — verdict: ? — test: — commit: — perf: —
- [ ] V-0560 CVE-2026-32883 (botan) name-constraint-bypass: X.509 path verification omitted checking OCSP response signature validity, allowing MitM to insert forged OCSP
      ours: src/crypto/pki (OCSP response signature check) — verdict: ? — test: — commit: — perf: —
- [ ] V-0561 CVE-2026-32884 (botan) hostname-mismatch: Bypass of name constraint exclusion in CN fallback case: mixed-case CN fields bypassed DNS nameConstraint chec
      ours: src/crypto/pki (CN fallback hostname matching, case folding) — verdict: ? — test: — commit: — perf: —
- [ ] V-0562 CVE-2024-34702 (botan) name-constraint-bypass: Checking name constraints in X.509 certificates is quadratic in the number of names, allowing DoS via large ce
      ours: src/crypto/pki (name constraints evaluation complexity) — verdict: ? — test: — commit: — perf: —
- [ ] V-0563 CVE-2024-39312 (botan) name-constraint-bypass: X.509 nameConstraint parsing ignored excluded subtrees when both permitted and excluded subtrees were present,
      ours: src/crypto/pki (name constraints, permitted vs excluded subtree logic) — verdict: ? — test: — commit: — perf: —
- [ ] V-0564 CVE-2018-9127 (botan) hostname-mismatch: RFC 6125 wildcard hostname matching incorrectly validated certificates such as b*.domain.com against unintende
      ours: src/crypto/pki (wildcard hostname matching) — verdict: ? — test: — commit: — perf: —
- [ ] V-0565 CVE-2023-33201 (bc-java) name-constraint-bypass: LDAP injection in X.509 certificate validation via unescaped Subject Name inserted into LDAP CertStore search 
      ours: not directly applicable: our SDK has no LDAP CertStore; informational — verdict: ? — test: — commit: — perf: —
- [ ] V-0566 CVE-2023-33202 (bc-java) der-length-overflow: PEMParser DoS via crafted ASN.1 data causing OutOfMemoryError when parsing X.509 certs/PKCS8 keys/PKCS7 object
      ours: src/crypto/pki (PEM/ASN.1 parsing, unbounded allocation from length field) — verdict: ? — test: — commit: — perf: —
- [ ] V-0567 CVE-2024-34447 (bc-java) hostname-mismatch: BCJSSE hostname verification could be performed against a DNS-resolved IP address instead of the intended host
      ours: src/crypto/pki (hostname verification input, hostname vs IP confusion) — verdict: ? — test: — commit: — perf: —
- [ ] V-0568 CVE-2026-5588 (bc-java) signature-malleability: PKIX draft CompositeVerifier in bcpkix accepts empty signature sequences as valid (broken/risky signature veri
      ours: src/crypto/pki (composite/multi-signature verification, empty-sequence acceptance) — verdict: ? — test: — commit: — perf: —
- [ ] V-0569 GHSA-8qv2-5vq6-g2g7 (webpki) ca-bit: CPU denial of service in certificate path building: exponential time with number of candidate certificates per
      ours: src/crypto/pki (chain/path building algorithm complexity) — verdict: ? — test: — commit: — perf: —
- [ ] V-0570 GHSA-fh2r-99q2-6mmg (rustls-webpki) ca-bit: CPU denial of service in certificate path building (same exponential-complexity class as briansmith/webpki, in
      ours: src/crypto/pki (chain/path building algorithm complexity) — verdict: ? — test: — commit: — perf: —
- [ ] V-0571 GHSA-xgp8-3hg3-c2mh (rustls-webpki) name-constraint-bypass: Name constraints were accepted for certificates asserting a wildcard DNS name: a permitted subtree of accept.e
      ours: src/crypto/pki (name constraints vs wildcard SAN interaction) — verdict: ? — test: — commit: — perf: —
- [ ] V-0572 GHSA-965h-392x-2mh5 (rustls-webpki) name-constraint-bypass: Name constraints for URI names were ignored and therefore effectively accepted (unenforced constraint type).
      ours: src/crypto/pki (name constraints, URI SAN type) — verdict: ? — test: — commit: — perf: —
- [ ] V-0573 GHSA-pwjx-qhcg-rvj4 (rustls-webpki) name-constraint-bypass: CRLs not considered authoritative by Distribution Point due to faulty matching: only the first of multiple dis
      ours: src/crypto/pki (CRL distribution point matching / revocation check) — verdict: ? — test: — commit: — perf: —
- [ ] V-0574 GHSA-82j2-j2ch-gfr8 (rustls-webpki) der-length-overflow: Denial of service via panic on malformed CRL BIT STRING: bit_string_flags() underflows raw_bits.len()-1 when p
      ours: src/crypto/pki (BIT STRING / DER length parsing for named-bit fields like KeyUsage) — verdict: ? — test: — commit: — perf: —
- [ ] V-0575 CVE-2018-16875 (go-crypto-x509) ca-bit: crypto/x509 does not limit the amount of work performed for each certificate chain verification, allowing craf
      ours: src/crypto/pki (chain building complexity) — verdict: ? — test: — commit: — perf: —
- [ ] V-0576 CVE-2019-17596 (go-crypto-x509) der-length-overflow: Remote DoS in Go 1.13 exploitable through TLS and SSH via DSA parameter validation issues in crypto/x509.
      ours: src/crypto/pki (DSA out of our scope; parameter validation pattern relevant) — verdict: ? — test: — commit: — perf: —
- [ ] V-0577 CVE-2020-7919 (go-crypto-x509) der-length-overflow: Malformed X.509 certificate causes a client panic (Go before 1.12.16 / 1.13.7), deliverable via crypto/tls con
      ours: src/crypto/pki (certificate parsing, malformed input handling) — verdict: ? — test: — commit: — perf: —
- [ ] V-0578 CVE-2025-58188 (go-crypto-x509) der-length-overflow: crypto/x509 certificate chain validation panics when a chain contains a DSA public key, enabling DoS.
      ours: src/crypto/pki (public key type dispatch in chain validation; DSA not in our scope but the dispatch-panic pattern is relevant to our own key-type switch) — verdict: ? — test: — commit: — perf: —
- [ ] V-0579 CVE-2025-61729 (go-crypto-x509) hostname-mismatch: HostnameError.Error() prints an unbounded number of mismatched hosts and builds the error text via repeated st
      ours: src/crypto/pki (hostname mismatch error path, SAN count handling) — verdict: ? — test: — commit: — perf: —
- [ ] V-0580 CVE-2025-61727 (go-crypto-x509) name-constraint-bypass: Excluded DNS name constraints were not applied when verifying wildcard SANs: a constraint excluding test.examp
      ours: src/crypto/pki (name constraints vs wildcard SAN matching) — verdict: ? — test: — commit: — perf: —
- [ ] V-0581 CVE-2025-76935 (go-crypto-x509) name-constraint-bypass: Regression from the CVE-2025-61727 fix: a single-label excluded DNS name constraint (e.g. a bare TLD) incorrec
      ours: src/crypto/pki (name constraints, single-label constraint edge case) — verdict: ? — test: — commit: — perf: —
- [ ] V-0582 CVE-2026-32280 (go-crypto-x509) ca-bit: During certificate chain building, the amount of work performed is not correctly limited when a large number o
      ours: src/crypto/pki (chain building candidate-intermediate complexity) — verdict: ? — test: — commit: — perf: —
- [ ] V-0583 CVE-2022-3602 (openssl) punycode-overflow: Punycode: 4-byte stack buffer overflow in ossl_punycode_decode during X.509 email-address name-constraint chec
      ours: src/crypto/pki (punycode decode for email SAN / name constraints) — verdict: ? — test: — commit: — perf: —
- [ ] V-0584 CVE-2022-3786 (openssl) punycode-overflow: Punycode: variable-length buffer overflow (attacker controls only the count of '.' bytes written, not content)
      ours: src/crypto/pki (punycode decode for email SAN / name constraints) — verdict: ? — test: — commit: — perf: —
- [ ] V-0585 CVE-2023-0464 (openssl) ca-bit: X.509 policy constraint verification is exponential in the number of policies/constraints in a crafted certifi
      ours: src/crypto/pki (policy constraint evaluation complexity) — verdict: ? — test: — commit: — perf: —
- [ ] V-0586 CVE-2023-0465 (openssl) name-constraint-bypass: Invalid certificate policies in leaf certificates are silently ignored, skipping other policy checks for that 
      ours: src/crypto/pki (policy constraint validation, error-ignore path) — verdict: ? — test: — commit: — perf: —
- [ ] V-0587 CVE-2023-0466 (openssl) name-constraint-bypass: X509_VERIFY_PARAM_add0_policy() is documented to implicitly enable the certificate policy check but the implem
      ours: src/crypto/pki (policy-check enable flag wiring) — verdict: ? — test: — commit: — perf: —
- [ ] V-0588 CVE-2021-3450 (openssl) ca-bit: CA certificate check bypass with X509_V_FLAG_X509_STRICT: an added check disallowing explicit EC parameters in
      ours: src/crypto/pki (chain validation flag interaction, CA-bit check being overwritten by a later check) — verdict: ? — test: — commit: — perf: —
- [ ] V-0589 CVE-2022-0778 (openssl) der-length-overflow: Infinite loop in BN_mod_sqrt() reachable when parsing a certificate with EC public key points in compressed fo
      ours: src/crypto/pki (EC public key point decompression during certificate parsing) + src/crypto/asymmetric (modular sqrt must validate/bound iterations, and our SDK's named-curve-only design should make non-prime moduli structurally unreachable -- worth a regression test) — verdict: ? — test: — commit: — perf: —
- [ ] V-0590 CVE-2018-0739 (openssl) der-length-overflow: Constructed ASN.1 types with a recursive definition (e.g. PKCS7) could exceed the stack, causing a DoS via sta
      ours: src/crypto/pki (ASN.1/DER parser recursion depth limit) — verdict: ? — test: — commit: — perf: —
- [ ] V-0591 CVE-2020-1971 (openssl) der-length-overflow: GENERAL_NAME_cmp misbehaves when comparing two X.509 GeneralName values that both contain an EDIPartyName, cau
      ours: src/crypto/pki (GeneralName/SAN comparison, EDIPartyName type handling) — verdict: ? — test: — commit: — perf: —
- [ ] V-0592 CVE-2021-3712 (openssl) der-length-overflow: Read buffer overruns processing ASN.1 strings: many OpenSSL functions assume ASN1_STRING data is NUL-terminate
      ours: src/crypto/pki (ASN1_STRING / DirectoryString handling: any string field pulled from a certificate must carry and respect an explicit length, never rely on NUL-termination) — verdict: ? — test: — commit: — perf: —
- [ ] V-0593 CVE-2021-23841 (openssl) der-length-overflow: X509_issuer_and_serial_hash() fails to handle an error when parsing a maliciously constructed issuer field in 
      ours: src/crypto/pki (issuer/serial hashing helper: must check the return value of the underlying issuer-name parse before using it) — verdict: ? — test: — commit: — perf: —
- [ ] V-0594 CVE-2022-3996 (openssl) ca-bit: X.509 policy constraint processing recursive-locking bug: a malformed certificate chain with policy constraint
      ours: src/crypto/pki (policy constraint evaluation; must not deadlock/hang regardless of locking primitive used, chain-of-death-adjacent DoS) — verdict: ? — test: — commit: — perf: —
- [ ] V-0595 L-0036 (OpenSSL punycode decoding buff) buffer-overflow: 
      ours: buffer-overflow — verdict: ? — test: — commit: — perf: —
- [ ] V-0596 L-0037 (X.509 name-constraint bypass v) name-constraint-bypass: 
      ours: name-constraint-bypass — verdict: ? — test: — commit: — perf: —
- [ ] V-0597 S-5280-6.1-1 (RFC 5280) path validation MUST provide equivalent functionality: conforming implementations are not required to implement this exact algorithm but MUST pro
      ours: path-validation-shortcut — verdict: ? — test: — commit: — perf: —
- [ ] V-0598 S-5280-6.1-2 (RFC 5280) unsupported critical extension MUST be rejected: clients MUST reject the certificate if it contains an unsupported critical extension; clie
      ours: critical-extension-bypass — verdict: ? — test: — commit: — perf: —
- [ ] V-0599 S-5280-6.1-3 (RFC 5280) path validation is relative to current time only: the algorithm validates with respect to current date/time; implementations MAY support val
      ours: validity-period-bypass — verdict: ? — test: — commit: — perf: —
- [ ] V-0600 S-5280-6.1-4 (RFC 5280) certificate MUST NOT appear more than once in a path: a certificate MUST NOT appear more than once in a prospective certification path
      ours: path-cycle — verdict: ? — test: — commit: — perf: —
- [ ] V-0601 S-5280-6.1.3-1 (RFC 5280) basic certificate processing checks (a)-(d): for each certificate i the implementation MUST verify the signature against working_public
      ours: signature-algorithm-mismatch — verdict: ? — test: — commit: — perf: —
- [ ] V-0602 S-5280-6.1.3-2 (RFC 5280) permitted_subtrees enforcement: unless the certificate is self-issued and not final, the implementation MUST verify the su
      ours: name-constraint-bypass — verdict: ? — test: — commit: — perf: —
- [ ] V-0603 S-5280-6.1.3-3 (RFC 5280) excluded_subtrees enforcement: unless self-issued and not final, the implementation MUST verify the subject name and ever
      ours: name-constraint-bypass — verdict: ? — test: — commit: — perf: —
- [ ] V-0604 S-5280-6.1.3-4 (RFC 5280) explicit_policy / valid_policy_tree requirement: the implementation MUST verify that either explicit_policy is greater than 0 or the valid_
      ours: policy-constraint-bypass — verdict: ? — test: — commit: — perf: —
- [ ] V-0605 S-5280-6.1.4-1 (RFC 5280) basicConstraints cA=TRUE required for v3 intermediates: if certificate i is version 3, the implementation MUST verify basicConstraints is present 
      ours: ca-bit — verdict: ? — test: — commit: — perf: —
- [ ] V-0606 S-5280-6.1.4-2 (RFC 5280) keyUsage keyCertSign bit required to sign certificates: if a key usage extension is present, the implementation MUST verify the keyCertSign bit is
      ours: key-usage-bypass — verdict: ? — test: — commit: — perf: —
- [ ] V-0607 S-5280-6.1.4-3 (RFC 5280) max_path_length decrement and pathLenConstraint enforcement: if the certificate was not self-issued, the implementation MUST verify max_path_length is 
      ours: path-length-bypass — verdict: ? — test: — commit: — perf: —
- [ ] V-0608 S-5280-8-1 (RFC 5280) certificates/CRLs need no confidentiality: since certificates and CRLs are digitally signed, no additional integrity service is neces
      ours: n-a-informational — verdict: ? — test: — commit: — perf: —
- [ ] V-0609 S-5280-8-3 (RFC 5280) single key pair for signature and key management discouraged: use of a single key pair for both signature and other purposes is strongly discouraged; se
      ours: key-reuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0610 S-5280-8-4 (RFC 5280) CA private key compromise enables bogus certificate issuance: if such compromise is detected, all certificates issued to the compromised CA MUST be revo
      ours: ca-key-compromise — verdict: ? — test: — commit: — perf: —
- [ ] V-0611 S-5280-8-6 (RFC 5280) stale or unavailable revocation information reduces assurance: CAs SHOULD take extra care when revocation info requires critical-extension support not ma
      ours: revocation-bypass — verdict: ? — test: — commit: — perf: —
- [ ] V-0612 S-5280-8-8 (RFC 5280) substituted trust-anchor public key subverts path validation: the path validation algorithm relies on the integrity of trusted CA information, especiall
      ours: trust-anchor-substitution — verdict: ? — test: — commit: — perf: —
- [ ] V-0613 S-5280-8-9 (RFC 5280) short keys or weak hash algorithms weaken the binding: the binding between key and subject cannot be stronger than the cryptographic module and a
      ours: signature-algorithm-mismatch — verdict: ? — test: — commit: — perf: —
- [ ] V-0614 S-5280-8-10 (RFC 5280) inconsistent name comparison causes acceptance/rejection errors: this specification relaxes X.500 name comparison rules, requiring support for binary compa
      ours: name-comparison-inconsistency — verdict: ? — test: — commit: — perf: —
- [ ] V-0615 S-5280-8-11 (RFC 5280) subject/issuer DN encoding mismatch breaks chain building: CAs MUST encode the distinguished name in the subject field of a CA certificate identicall
      ours: name-comparison-inconsistency — verdict: ? — test: — commit: — perf: —
- [ ] V-0616 S-5280-8-12 (RFC 5280) name constraint encoding mismatch defeats excludedSubtrees/permittedSubtrees: name constraints for distinguished names MUST be stated identically to the encoding used i
      ours: name-constraint-bypass — verdict: ? — test: — commit: — perf: —
- [ ] V-0617 S-5280-8-13 (RFC 5280) name constraints on one name form give no protection for other forms: using nameConstraints to constrain one name form (e.g. DNS names) offers no protection aga
      ours: name-constraint-bypass — verdict: ? — test: — commit: — perf: —
- [ ] V-0618 S-5280-8-14 (RFC 5280) issuer name collisions across unrelated CAs: CA and CRL issuer names SHOULD be formed to reduce collision likelihood; implementations v
      ours: issuer-name-collision — verdict: ? — test: — commit: — perf: —
- [ ] V-0619 S-5280-8-15 (RFC 5280) emailAddress case sensitivity mismatch: implementers should not include an email address in the emailAddress attribute if the host
      ours: name-comparison-inconsistency — verdict: ? — test: — commit: — perf: —
- [ ] V-0620 S-5280-8-16 (RFC 5280) malicious links in CRL distribution point / AIA extensions: implementers should always validate retrieved data to ensure it is properly formed before 
      ours: der-length-overflow — verdict: ? — test: — commit: — perf: —
- [ ] V-0621 S-5280-8-17 (RFC 5280) circular https CRL/AIA dependency causes unbounded recursion: CAs SHOULD NOT include https/ldaps URIs in these extensions; CAs that do MUST ensure the s
      ours: unbounded-recursion — verdict: ? — test: — commit: — perf: —
- [ ] V-0622 S-5280-8-18 (RFC 5280) self-issued certificates for CA key rollover: conforming client implementations process the self-issued certificate to determine whether
      ours: n-a-informational — verdict: ? — test: — commit: — perf: —
- [ ] V-0623 S-5280-8-19 (RFC 5280) TeletexString misinterpreted as Latin1String: name comparison rules assume TeletexStrings are encoded per the ASN.1 standard; comparison
      ours: name-comparison-inconsistency — verdict: ? — test: — commit: — perf: —
- [ ] V-0624 S-5280-8-20 (RFC 5280) visually confusable characters in displayed names: issuers and relying parties both need to be aware that different internal strings can shar
      ours: hostname-mismatch — verdict: ? — test: — commit: — perf: —
- [ ] V-0625 S-6125-7.1-1 (RFC 6125) pinned certificate context must be validated as a whole: the cached name association MUST take account of both the presented certificate and the fu
      ours: hostname-mismatch — verdict: ? — test: — commit: — perf: —
- [ ] V-0626 S-6125-7.2-1 (RFC 6125) wildcard rules tightened versus legacy practice: the wildcard character '*' SHOULD NOT be included in presented identifiers but MAY be chec
      ours: n-a-informational — verdict: ? — test: — commit: — perf: —
- [ ] V-0627 S-6125-7.2-2 (RFC 6125) wildcard certificates vouch for any host in the domain: cited attacks [Defeating-SSL], [HTTPSbytes] show real exploitation; the spec response is t
      ours: hostname-mismatch — verdict: ? — test: — commit: — perf: —
- [ ] V-0628 S-6125-7.2-3 (RFC 6125) ambiguous wildcard placement rules across implementations: this specification restricts wildcards to the entire left-most label only, eliminating amb
      ours: hostname-mismatch — verdict: ? — test: — commit: — perf: —
- [ ] V-0629 S-6125-7.2-4 (RFC 6125) wildcard embedded in internationalized A-labels/U-labels is undefined: implementations are strongly discouraged from including or checking for a wildcard embedde
      ours: hostname-mismatch — verdict: ? — test: — commit: — perf: —
- [ ] V-0630 S-6125-7.3-1 (RFC 6125) internationalized domain names permit confusable characters: n/a defense specified in this section beyond noting the risk; see [IDNA-DEFS] for discussi
      ours: hostname-mismatch — verdict: ? — test: — commit: — perf: —
- [ ] V-0631 S-6125-7.4-1 (RFC 6125) single certificate for multiple domains without SNI: TLS SNI lets the client indicate the desired domain so the server can return the appropria
      ours: n-a-informational — verdict: ? — test: — commit: — perf: —
- [ ] V-0632 S-9525-7.1-1 (RFC 9525) wildcard certificates vouch for any single-label hostname: restricting presented identifiers to one wildcard character in the left-most label only mi
      ours: hostname-mismatch — verdict: ? — test: — commit: — perf: —
- [ ] V-0633 S-9525-7.1-2 (RFC 9525) left-most-label-only wildcard restriction: restrict presented identifiers to only one wildcard character and restrict wildcard use to
      ours: hostname-mismatch — verdict: ? — test: — commit: — perf: —
- [ ] V-0634 S-9525-7.1-3 (RFC 9525) cleartext HTTP upgrade to HTTPS hijack (sslstrip-class): administrators and software developers are advised to follow strict TLS guidelines (HSTS-s
      ours: hostname-mismatch — verdict: ? — test: — commit: — perf: —
- [ ] V-0635 S-9525-7.1-4 (RFC 9525) XSS-driven exploitation of wildcard certs: web browsers and applications are advised to follow XSS best practices (e.g. OWASP guidanc
      ours: hostname-mismatch — verdict: ? — test: — commit: — perf: —
- [ ] V-0636 S-9525-7.1-5 (RFC 9525) public-suffix wildcard out of scope: n/a: protection against public-suffix wildcards is explicitly out of scope of this documen
      ours: hostname-mismatch — verdict: ? — test: — commit: — perf: —
- [ ] V-0637 S-9525-7.1-6 (RFC 9525) application protocols may disallow wildcards entirely: application protocols can disallow the use of wildcard certificates entirely as a more foo
      ours: hostname-mismatch — verdict: ? — test: — commit: — perf: —
- [ ] V-0638 S-9525-7.4-1 (RFC 9525) IP address string misclassified as FQDN across components: consistent classification of identifiers across all components of a system avoids this pro
      ours: hostname-mismatch — verdict: ? — test: — commit: — perf: —
- [ ] V-0639 S-9525-7.5-1 (RFC 9525) shared certificate across many names has weakest-link fate-sharing: limit the number of names any server can speak for, and ensure all servers in the set main
      ours: hostname-mismatch — verdict: ? — test: — commit: — perf: —
- [ ] V-0640 S-9525-7.6-1 (RFC 9525) name constraints only apply to explicitly enumerated name forms: a client using multiple reference-identifier types SHOULD ensure the issuing CA is appropr
      ours: name-constraint-bypass — verdict: ? — test: — commit: — perf: —
- [ ] V-0641 S-9525-7.7-1 (RFC 9525) trusting a CA implies trusting all its issued certificates: the certificate checking process in this document does not include checks for bad behavior
      ours: n-a-informational — verdict: ? — test: — commit: — perf: —
- [ ] V-0642 S-7468-sec-1 (RFC 7468) PEM data from untrusted sources must be parsed defensively: parsers must be prepared to handle unexpected data without causing security vulnerabilitie
      ours: der-length-overflow — verdict: ? — test: — commit: — perf: —
- [ ] V-0643 S-7468-sec-2 (RFC 7468) PEM has no canonical encoding, enabling ambiguity and side channels: if canonical encodings/fingerprinting are needed, the encoded structure must be decoded an
      ours: der-length-overflow — verdict: ? — test: — commit: — perf: —

## HTTP/3, QPACK, HTTP Datagrams (RFC 9114/9204/9297/9220/9218)

- [ ] V-0421 GHSA-vvgj-x9jq-8cj9 (quic-go) resource-exhaustion-pre-handshake: HTTP/3 trailer frames encoded with QPACK can decode into very large header field sections, similar to CVE-2025
      ours: QPACK decoder header-list size accounting for HTTP/3 trailer frames (missing/incorrect max header list size enforcement) — verdict: ? — test: — commit: — perf: —
- [ ] V-0422 GHSA-g754-hx8w-x2g6 (quic-go) resource-exhaustion-pre-handshake: Excessive memory allocation through QPACK-encoded HTTP/3 HEADERS frames that decode into very large header fie
      ours: QPACK decoder header-list size accounting for HTTP/3 HEADERS frames (missing enforcement of SETTINGS_MAX_FIELD_SECTION_SIZE before allocation) — verdict: ? — test: — commit: — perf: —
- [ ] V-0423 CVE-2026-12523 (quiche) resource-exhaustion-pre-handshake: HTTP/3 resource exhaustion via frame pre-allocation: a peer can send frame headers advertising large sizes cau
      ours: HTTP/3 frame length field must be bounded/validated before buffer pre-allocation, independent of stream flow-control limits — verdict: ? — test: — commit: — perf: —
- [ ] V-0424 CVE-2022-30592 (lsquic) nil-deref/crash-on-frame: liblsquic/lsquic_qenc_hdl.c in LiteSpeed QUIC (LSQUIC) before 3.1.0 mishandles MAX_TABLE_CAPACITY, leading to 
      ours: QPACK encoder-stream MAX_TABLE_CAPACITY instruction handling must validate the requested capacity before applying it to the dynamic table state — verdict: ? — test: — commit: — perf: —
- [ ] V-0425 GHSA-6w86-wgwq-rgq8 (neqo-transport) integer-overflow: Integer overflow in neqo-qpack's dynamic-table indexing: an unsanitized QPACK index can trigger panics in debu
      ours: QPACK dynamic table index arithmetic (relative/absolute index conversion) must be bounds-checked before table access — verdict: ? — test: — commit: — perf: —
- [ ] V-0426 GHSA-mj42-367w-cf98 (neqo-transport) resource-exhaustion-pre-handshake: LiteralReader::read() in the QPACK decoder resizes a vector based on an unchecked network-supplied varint leng
      ours: QPACK Huffman/literal string length varint must be bounds-checked against a maximum before being used to size an allocation — verdict: ? — test: — commit: — perf: —
- [ ] V-0427 CVE-2022-4925 (chromium (QUIC)) header-injection: Insufficient validation of untrusted input in QUIC in Google Chrome allowed a remote attacker to perform heade
      ours: app/http3 response header field validation (forbidden characters, pseudo-header ordering) — verdict: ? — test: — commit: — perf: —
- [ ] V-0428 CVE-2024-24989 (nginx (ngx_http_v3_module)) null-deref: NULL pointer dereference in the HTTP/3 module: a crafted sequence of QUIC/HTTP/3 frames could cause the worker
      ours: app/http3 stream/request state machine early-frame handling before request object is fully initialized — verdict: ? — test: — commit: — perf: —
- [ ] V-0429 CVE-2024-24990 (nginx (ngx_http_v3_module)) use-after-free: Use-after-free in the HTTP/3 module triggerable by a crafted stream/request lifecycle sequence. Affects 1.25.0
      ours: app/http3 request object teardown vs. pending stream callbacks — verdict: ? — test: — commit: — perf: —
- [ ] V-0430 CVE-2024-32760 (nginx (ngx_http_v3_module)) buffer-overflow: Buffer overwrite in the HTTP/3 module: crafted client input caused a worker process crash, memory disclosure, 
      ours: app/http3 or app/qpack field/frame buffer sizing against attacker-controlled lengths — verdict: ? — test: — commit: — perf: —
- [ ] V-0431 CVE-2024-31079 (nginx (ngx_http_v3_module)) stack-overflow: Stack overflow and use-after-free in the HTTP/3 module: crafted client input caused a worker process crash, me
      ours: app/http3 recursive or deeply-nested frame/field parsing — verdict: ? — test: — commit: — perf: —
- [ ] V-0432 CVE-2024-35200 (nginx (ngx_http_v3_module)) null-deref: NULL pointer dereference in the HTTP/3 module causing a worker process crash on crafted client input. Affects 
      ours: app/http3 stream state checks before dereferencing per-stream context — verdict: ? — test: — commit: — perf: —
- [ ] V-0433 CVE-2024-34161 (nginx (ngx_http_v3_module)) oob-read: Memory disclosure in the HTTP/3 module: crafted client input could leak uninitialized or stale worker memory b
      ours: app/http3 or app/qpack field decode reading past a bounds-checked buffer — verdict: ? — test: — commit: — perf: —
- [ ] V-0434 CVE-2026-42530 (nginx (ngx_http_v3_module)) use-after-free: Use-after-free in HTTP/3 that could allow denial of service or potential remote code execution via specially c
      ours: app/http3 or app/qpack request/stream teardown ordering (QPACK decoder edge cited by third-party writeups) — verdict: ? — test: — commit: — perf: —
- [ ] V-0435 CVE-2026-33555 (haproxy (HTTP/3)) request-smuggling: HTTP/3-to-HTTP/1 desync: HAProxy's HTTP/3 parser accepted a request whose Content-Length header did not match 
      ours: app/http3 request framing translated to HTTP/1.1 backend connection reuse; Content-Length vs. actual body length reconciliation — verdict: ? — test: — commit: — perf: —
- [ ] V-0436 CVE-2024-34362 (envoy (QUIC/HTTP3)) use-after-free: Use-after-free in EnvoyQuicServerStream: a QUIC RESET_STREAM frame received without a preceding STOP_SENDING s
      ours: app/http3 stream-reset handling (RESET_STREAM without STOP_SENDING) vs. idle-timeout local-response path — verdict: ? — test: — commit: — perf: —
- [ ] V-0437 GHSA-p7c7-7c47-pwch (envoy (QUIC/HTTP3, QPACK)) qpack-dyntable-exhaustion: Denial-of-service via QPACK blocked decoding: an attacker sends a HEADERS frame whose QPACK header-block prefi
      ours: app/qpack blocked-stream buffering accounted against QUIC stream flow control credit — verdict: ? — test: — commit: — perf: —
- [ ] V-0438 L-0021 (HTTP/2 Rapid Reset and its HTT) stream-reset-flood: 
      ours: stream-reset-flood — verdict: ? — test: — commit: — perf: —
- [ ] V-0439 S-9114-10.1-1 (RFC 9114) server authority relies on HTTP authority rules: the security considerations of establishing authority are discussed in Section 17.1 of [HT
      ours: n-a-informational — verdict: ? — test: — commit: — perf: —
- [ ] V-0440 S-9114-10.2-1 (RFC 9114) ALPN establishes protocol before payload processing: use of ALPN in the TLS and QUIC handshakes establishes the target application protocol bef
      ours: cross-protocol-attack — verdict: ? — test: — commit: — perf: —
- [ ] V-0441 S-9114-10.2-2 (RFC 9114) ALPN does not prevent all cross-protocol attacks: ALPN does not guarantee protection from all cross-protocol attacks; see Section 21.5 of [Q
      ours: cross-protocol-attack — verdict: ? — test: — commit: — perf: —
- [ ] V-0442 S-9114-10.3-1 (RFC 9114) HTTP/3 field names not valid in HTTP/1.1 must not be downgraded: requests or responses containing invalid field names MUST be treated as malformed, so an i
      ours: intermediary-encapsulation — verdict: ? — test: — commit: — perf: —
- [ ] V-0443 S-9114-10.3-2 (RFC 9114) CR/LF/NUL in field values can be exploited if translated verbatim: any request or response containing a character not permitted by the 'field-content' ABNF r
      ours: intermediary-encapsulation — verdict: ? — test: — commit: — perf: —
- [ ] V-0444 S-9114-10.4-1 (RFC 9114) multi-tenant server push cache poisoning: a server MUST ensure tenants are not able to push representations of resources they do not
      ours: cache-poisoning — verdict: ? — test: — commit: — perf: —
- [ ] V-0445 S-9114-10.5-1 (RFC 9114) HTTP/3 connections demand more resources than HTTP/1.1/2: settings for field compression and flow control ensure memory commitments for these featur
      ours: settings-abuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0446 S-9114-10.5-2 (RFC 9114) excessive PUSH_PROMISE issuance: a client that accepts server push SHOULD limit the number of push IDs it issues at a time
      ours: stream-reset-flood — verdict: ? — test: — commit: — perf: —
- [ ] V-0447 S-9114-10.5-4 (RFC 9114) abuse of ignorable protocol elements to burn CPU: implementations SHOULD track the use of these features and set limits; an endpoint MAY tre
      ours: settings-abuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0448 S-9114-10.5-5 (RFC 9114) field-section compression can waste processing resources: see Section 7 of [QPACK] for details on potential abuses of field compression processing
      ours: header-compression-bomb — verdict: ? — test: — commit: — perf: —
- [ ] V-0449 S-9114-10.5-6 (RFC 9114) unmonitored feature use exposes DoS risk: an endpoint that does not monitor such behavior exposes itself to denial-of-service risk; 
      ours: settings-abuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0450 S-9114-10.5.1-1 (RFC 9114) unbounded field section size forces large memory commitment: an endpoint can advertise SETTINGS_MAX_FIELD_SECTION_SIZE, but it is only advisory; peers 
      ours: header-compression-bomb — verdict: ? — test: — commit: — perf: —
- [ ] V-0451 S-9114-10.5.2-1 (RFC 9114) CONNECT creates disproportionate load on a proxy: a proxy supporting CONNECT might be more conservative in the number of simultaneous reques
      ours: stream-reset-flood — verdict: ? — test: — commit: — perf: —
- [ ] V-0452 S-9114-10.5.2-2 (RFC 9114) TIME_WAIT resource retention after CONNECT stream closes: a proxy might delay increasing QUIC stream limits for some time after a TCP connection ter
      ours: stream-reset-flood — verdict: ? — test: — commit: — perf: —
- [ ] V-0453 S-9114-10.6-1 (RFC 9114) compression side channel (BREACH-class): implementations MUST NOT compress content that includes both confidential and attacker-con
      ours: header-compression-bomb — verdict: ? — test: — commit: — perf: —
- [ ] V-0454 S-9114-10.7-1 (RFC 9114) padding provides limited, easily-defeated protection: disabling or limiting compression is preferable to relying on padding as the primary count
      ours: header-compression-bomb — verdict: ? — test: — commit: — perf: —
- [ ] V-0455 S-9114-10.8-1 (RFC 9114) nested length fields in frame parsing are a security risk: an implementation MUST ensure that the length of a frame exactly matches the length of the
      ours: der-length-overflow — verdict: ? — test: — commit: — perf: —
- [ ] V-0456 S-9114-10.9-1 (RFC 9114) 0-RTT with HTTP/3 exposes replay attacks: the anti-replay mitigations in [HTTP-REPLAY] MUST be applied when using HTTP/3 with 0-RTT,
      ours: replay-attack — verdict: ? — test: — commit: — perf: —
- [ ] V-0457 S-9114-10.10-1 (RFC 9114) client address change during connection migration: implementations need to either actively retrieve the client's current address when relevan
      ours: n-a-informational — verdict: ? — test: — commit: — perf: —
- [ ] V-0458 S-9114-10.11-1 (RFC 9114) settings and timing enable client/server fingerprinting: n/a defense named beyond noting the risk as an observable behavioral difference
      ours: n-a-informational — verdict: ? — test: — commit: — perf: —
- [ ] V-0459 S-9114-10.11-2 (RFC 9114) single-connection preference enables activity correlation across origins: n/a defense named beyond noting the privacy risk
      ours: n-a-informational — verdict: ? — test: — commit: — perf: —
- [ ] V-0460 S-9114-10.11-3 (RFC 9114) immediate-response features enable latency measurement: n/a defense named beyond noting the privacy risk
      ours: n-a-informational — verdict: ? — test: — commit: — perf: —
- [ ] V-0461 S-9204-7-1 (RFC 9204) QPACK security concern overview: n/a
      ours: n-a-informational — verdict: ? — test: — commit: — perf: —
- [ ] V-0462 S-9204-7.1-1 (RFC 9204) dynamic table state probeable via encoded length: n/a (attack description; mitigations follow in 7.1.2)
      ours: header-compression-bomb — verdict: ? — test: — commit: — perf: —
- [ ] V-0463 S-9204-7.1-2 (RFC 9204) TLS/QUIC confidentiality does not hide length: n/a; length-hiding padding schemes only provide limited protection per the following note
      ours: header-compression-bomb — verdict: ? — test: — commit: — perf: —
- [ ] V-0464 S-9204-7.1-3 (RFC 9204) CRIME-class attack precedent: n/a (precedent; QPACK's field-line granularity mitigation described in 7.1.1)
      ours: header-compression-bomb — verdict: ? — test: — commit: — perf: —
- [ ] V-0465 S-9204-7.1.1-1 (RFC 9204) QPACK mitigates but does not prevent CRIME-class attacks: QPACK forces a guess to match an entire field line rather than individual characters, miti
      ours: header-compression-bomb — verdict: ? — test: — commit: — perf: —
- [ ] V-0466 S-9204-7.1.1-2 (RFC 9204) low-entropy field values remain recoverable: values with high entropy are unlikely to be recovered successfully; only low-entropy value
      ours: header-compression-bomb — verdict: ? — test: — commit: — perf: —
- [ ] V-0467 S-9204-7.1.1-3 (RFC 9204) mutually distrustful entities sharing a compression context: n/a (attack scenario description; mitigations in 7.1.2)
      ours: header-compression-bomb — verdict: ? — test: — commit: — perf: —
- [ ] V-0468 S-9204-7.1.2-1 (RFC 9204) segregate dynamic table access by constructing entity: an ideal solution segregates dynamic table access based on the entity that constructed the
      ours: header-compression-bomb — verdict: ? — test: — commit: — perf: —
- [ ] V-0469 S-9204-7.1.2-2 (RFC 9204) penalize repeated-guess field lines to block adaptive probing: an encoder without provenance knowledge can introduce a penalty for many field lines with 
      ours: header-compression-bomb — verdict: ? — test: — commit: — perf: —
- [ ] V-0470 S-9204-7.1.2-3 (RFC 9204) intermediary re-encoding can merge separated compression contexts: this mitigation (context segregation) is most effective only between two endpoints, not ac
      ours: header-compression-bomb — verdict: ? — test: — commit: — perf: —
- [ ] V-0471 S-9204-7.1.2-4 (RFC 9204) evicting a dynamic table entry is ineffective if the attacker can force reinstallation: n/a (limitation noted; addressed instead by never-indexed literals in 7.1.3)
      ours: qpack-dyntable-exhaustion — verdict: ? — test: — commit: — perf: —
- [ ] V-0472 S-9204-7.1.3-1 (RFC 9204) never-indexed literal bit prevents downstream re-indexing: an intermediary MUST NOT re-encode a value using a literal representation with the 'N' bit
      ours: qpack-dyntable-exhaustion — verdict: ? — test: — commit: — perf: —
- [ ] V-0473 S-9204-7.1.3-2 (RFC 9204) low-entropy or sensitive fields should never be indexed: an encoder might choose not to index values with low entropy, or values for fields conside
      ours: qpack-dyntable-exhaustion — verdict: ? — test: — commit: — perf: —
- [ ] V-0474 S-9204-7.2-1 (RFC 9204) static Huffman encoding information leakage is not practically exploitable: n/a (residual risk accepted as impractical)
      ours: n-a-informational — verdict: ? — test: — commit: — perf: —
- [ ] V-0475 S-9204-7.3-1 (RFC 9204) attacker attempts to exhaust endpoint memory via QPACK state: QPACK is designed to limit both peak and stable memory via SETTINGS_QPACK_MAX_TABLE_CAPACI
      ours: qpack-dyntable-exhaustion — verdict: ? — test: — commit: — perf: —
- [ ] V-0476 S-9204-7.3-6 (RFC 9204) flow-control-blocked unsent data is not bounded by the table-size limit: implementations should limit the size of unsent data and may respond by limiting the peer'
      ours: qpack-dyntable-exhaustion — verdict: ? — test: — commit: — perf: —
- [ ] V-0477 S-9204-7.4-1 (RFC 9204) unbounded integers or string literals create security weaknesses: an implementation has to set a limit for accepted integer values and encoded lengths (Sect
      ours: der-length-overflow — verdict: ? — test: — commit: — perf: —
- [ ] V-0478 S-9204-7.4-2 (RFC 9204) oversized value MUST be a stream/connection error: if a value larger than decodable is encountered, this MUST be treated as a stream error of
      ours: der-length-overflow — verdict: ? — test: — commit: — perf: —
- [ ] V-0479 S-9297-4-1 (RFC 9297) SETTINGS_H3_DATAGRAM setting reveals HTTP Datagram support (probing): implementations that wish to avoid this fingerprinting are advised to always send the sett
      ours: n-a-informational — verdict: ? — test: — commit: — perf: —
- [ ] V-0480 S-9297-4-2 (RFC 9297) Capsule Protocol restricted to new upgrade tokens: since Capsule Protocol use is restricted to new HTTP upgrade tokens, it is not directly ac
      ours: n-a-informational — verdict: ? — test: — commit: — perf: —
- [ ] V-0481 S-9297-4-3 (RFC 9297) new upgrade tokens using capsules require their own security analysis: definitions of new HTTP upgrade tokens that use the Capsule Protocol need to include a sec
      ours: capsule-parsing — verdict: ? — test: — commit: — perf: —
- [ ] V-0482 S-9220-4-1 (RFC 9220) Extended CONNECT over HTTP/3 introduces no new considerations beyond RFC 8441: this document introduces no new security considerations beyond those discussed in [RFC8441
      ours: n-a-informational — verdict: ? — test: — commit: — perf: —
- [ ] V-0483 S-9218-15-1 (RFC 9218) server buffering of PRIORITY_UPDATE frames: see Section 7 of this document for considerations on bounding server buffering of PRIORITY
      ours: settings-abuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0484 S-9218-15-2 (RFC 9218) priority-based response starvation: see Section 10 for examples of how prioritization schemes can lead to starvation of certai
      ours: settings-abuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0485 S-9218-15-3 (RFC 9218) structured-field security considerations apply to priority parameters: the security considerations from [STRUCTURED-FIELDS] apply to the processing of priority p
      ours: settings-abuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0486 S-9221-6-1 (RFC 9221) DATAGRAM frame shares QUIC's general security properties: the security considerations of [RFC9000] apply to DATAGRAM frames; all application data tr
      ours: n-a-informational — verdict: ? — test: — commit: — perf: —
- [ ] V-0487 S-9221-6-2 (RFC 9221) 0-RTT DATAGRAM frames require a replay-safety profile: application protocols that allow DATAGRAM frames in 0-RTT require a profile defining accep
      ours: replay-attack — verdict: ? — test: — commit: — perf: —
- [ ] V-0488 S-9221-6-3 (RFC 9221) DATAGRAM use is distinguishable by loss-response fingerprinting: n/a defense named beyond noting this as a residual distinguishability property of the unre
      ours: n-a-informational — verdict: ? — test: — commit: — perf: —

## WebTransport (draft-ietf-webtrans-http3)

- [ ] V-0492 CVE-2026-21434 (webtransport-go (WebTransport)) resource-exhaustion: Memory exhaustion via oversized WT_CLOSE_SESSION Application Error Message: the draft mandates a 1024-byte lim
      ours: app/webtransport capsule parser must enforce the draft's fixed length limits on variable-length capsule fields before allocating/copying — verdict: ? — test: — commit: — perf: —
- [ ] V-0493 CVE-2026-21435 (webtransport-go (WebTransport)) resource-exhaustion: Indefinite session-close hang: a malicious peer can withhold QUIC flow-control credit on the CONNECT stream, b
      ours: app/webtransport session close must not block indefinitely on flow-control credit it does not control; needs a bound/timeout independent of peer cooperation — verdict: ? — test: — commit: — perf: —
- [ ] V-0494 CVE-2026-21438 (webtransport-go (WebTransport)) resource-exhaustion: Unbounded memory consumption via repeated creation and closing of many WebTransport streams: no limit on the r
      ours: app/webtransport stream table cleanup on close must be synchronous/bounded, and stream creation should be rate- or count-limited per session — verdict: ? — test: — commit: — perf: —
- [ ] V-0495 CVE-2026-57497 (webtransport-go (WebTransport, capsule parser)) resource-exhaustion: Memory exhaustion via unknown capsule buffering: when skipping an unrecognized WebTransport capsule type, the 
      ours: app/webtransport unknown/unsupported capsule types must be skipped by discarding the declared-length body, never buffered wholesale — verdict: ? — test: — commit: — perf: —
- [ ] V-0496 L-0038 (WebTransport session-close DoS) flow-control-blocking: 
      ours: flow-control-blocking — verdict: ? — test: — commit: — perf: —
- [ ] V-0497 L-0039 (WebTransport WT_CLOSE_SESSION ) unbounded-length-allocation: 
      ours: unbounded-length-allocation — verdict: ? — test: — commit: — perf: —
- [ ] V-0498 L-0040 (WebTransport unknown-capsule b) unbounded-length-allocation: 
      ours: unbounded-length-allocation — verdict: ? — test: — commit: — perf: —
- [ ] V-0499 S-webtrans-overview-6-1 (draft-ietf-webtrans-overview-13) Network access control for untrusted clients: Impose the common requirements of Section 2 (origin-scoped access, TLS mandate, server opt
      ours: spec-security-consideration — verdict: ? — test: — commit: — perf: —
- [ ] V-0500 S-webtrans-overview-6-2 (draft-ietf-webtrans-overview-13) Transport confidentiality and integrity: WebTransport mandates TLS for all protocols implementing it, providing confidentiality and
      ours: spec-security-consideration — verdict: ? — test: — commit: — perf: —
- [ ] V-0501 S-webtrans-overview-6-3 (draft-ietf-webtrans-overview-13) Network scanning via connection-error information disclosure: The user agent running untrusted clients MUST NOT provide detailed error information until
      ours: spec-security-consideration — verdict: ? — test: — commit: — perf: —
- [ ] V-0502 S-webtrans-overview-6-4 (draft-ietf-webtrans-overview-13) Optional TLS-based peer authentication: Individual transport protocols MAY expose TLS-based authentication capabilities such as cl
      ours: spec-security-consideration — verdict: ? — test: — commit: — perf: —
- [ ] V-0503 S-webtrans-h3-5.1-1 (draft-ietf-webtrans-http3-15) flow control MUST be enabled when sessions share a connection: a WebTransport endpoint that allows a session to share an underlying transport connection 
      ours: session-flow-control — verdict: ? — test: — commit: — perf: —
- [ ] V-0504 S-webtrans-h3-5.1-2 (draft-ietf-webtrans-http3-15) multiple sessions without negotiated flow control must be rejected: if flow control is not enabled, clients MUST NOT attempt to establish more than one simult
      ours: session-flow-control — verdict: ? — test: — commit: — perf: —
- [ ] V-0505 S-webtrans-h3-5.1-3 (draft-ietf-webtrans-http3-15) stale flow-control capsules must be ignored when flow control is not enabled: if flow control is not enabled, an endpoint MUST ignore receipt of any flow control capsul
      ours: session-flow-control — verdict: ? — test: — commit: — perf: —
- [ ] V-0506 S-webtrans-h3-5.2-1 (draft-ietf-webtrans-http3-15) unbounded rate of incoming WebTransport sessions: servers SHOULD limit the rate of incoming WebTransport sessions on HTTP/3 connections to p
      ours: session-flow-control — verdict: ? — test: — commit: — perf: —
- [ ] V-0507 S-webtrans-h3-8-1 (draft-ietf-webtrans-http3-15) WebTransport satisfies overview-level security requirements: WebTransport over HTTP/3 satisfies all of the security requirements imposed by [OVERVIEW] 
      ours: n-a-informational — verdict: ? — test: — commit: — perf: —
- [ ] V-0508 S-webtrans-h3-8-2 (draft-ietf-webtrans-http3-15) explicit opt-in prevents protocol-confusion attacks; Origin header gates browser access: WebTransport over HTTP/3 requires explicit opt-in via an HTTP/3 setting to avoid protocol 
      ours: cross-protocol-attack — verdict: ? — test: — commit: — perf: —
- [ ] V-0509 S-webtrans-h3-8-3 (draft-ietf-webtrans-http3-15) pooled sessions from different trust domains can exhaust shared resources: a WebTransport endpoint MUST implement flow control mechanisms if it allows session sharin
      ours: session-flow-control — verdict: ? — test: — commit: — perf: —
- [ ] V-0510 S-webtrans-h3-8-4 (draft-ietf-webtrans-http3-15) untrusted application opens too many sessions: when the application is untrusted, a WebTransport client SHOULD limit the number of outgoi
      ours: session-flow-control — verdict: ? — test: — commit: — perf: —
- [ ] V-0511 S-webtrans-h3-8-5 (draft-ietf-webtrans-http3-15) HTTP/3 DoS considerations apply to WebTransport: the denial-of-service considerations in Section 10.5 of [HTTP3] are relevant to WebTranspo
      ours: settings-abuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0512 S-webtrans-h3-8-6 (draft-ietf-webtrans-http3-15) new bidirectional interaction modes need monitoring: implementations SHOULD track the use of WebTransport features such as the number of incomi
      ours: datagram-flood — verdict: ? — test: — commit: — perf: —

## MoQT (draft-ietf-moq-transport)

- [ ] V-0783 L-0041 (MoQT shared per-session QUIC t) resource-contention: 
      ours: resource-contention — verdict: ? — test: — commit: — perf: —
- [ ] V-0784 S-moqt-13-1 (draft-ietf-moq-transport-19) MOQT is hop-by-hop, so security spans multiple relay hops: security considerations need to consider both what happens between two endpoints and the e
      ours: n-a-informational — verdict: ? — test: — commit: — perf: —
- [ ] V-0785 S-moqt-13-2 (draft-ietf-moq-transport-19) each hop must securely identify and authorize its peer: MOQT uses a per-hop trust model where endpoints need to be securely identified, authorized
      ours: n-a-informational — verdict: ? — test: — commit: — perf: —
- [ ] V-0786 S-moqt-13-3 (draft-ietf-moq-transport-19) relays must independently authorize every aggregated subscriber: subscription requests can carry authorization tokens (Section 13.3) to prove the subscribe
      ours: subscribe-flood — verdict: ? — test: — commit: — perf: —
- [ ] V-0787 S-moqt-13.1-1 (draft-ietf-moq-transport-19) subscription amplification / flood: relays SHOULD implement rate limiting on subscription requests and MAY reject excessive su
      ours: subscribe-flood — verdict: ? — test: — commit: — perf: —
- [ ] V-0788 S-moqt-13.1-2 (draft-ietf-moq-transport-19) cache poisoning in relays (TODO in spec, still a named threat): n/a: the spec explicitly marks this as a TODO ("Describe Cache Poisoning attacks") -- no d
      ours: cache-poisoning — verdict: ? — test: — commit: — perf: —
- [ ] V-0789 S-moqt-13.2-1 (draft-ietf-moq-transport-19) MOQT depends on a secure transport for confidentiality/integrity/authentication: MOQT depends on a secure transport (QUIC or WebTransport) to provide confidentiality, inte
      ours: n-a-informational — verdict: ? — test: — commit: — perf: —
- [ ] V-0790 S-moqt-13.2-2 (draft-ietf-moq-transport-19) traffic pattern analysis survives transport security: n/a defense named beyond noting the residual risk of traffic analysis despite basic transp
      ours: object-size-abuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0791 S-moqt-13.3-1 (draft-ietf-moq-transport-19) mutual TLS and token schemes for authorization: MOQT supports authorization via mutual TLS for endpoint-level identification and token-bas
      ours: n-a-informational — verdict: ? — test: — commit: — perf: —
- [ ] V-0792 S-moqt-13.3-2 (draft-ietf-moq-transport-19) mutual TLS provides only endpoint identity, not fine-grained authorization: only endpoint-level authentication is provided by mutual TLS; what a particular identified
      ours: subscribe-flood — verdict: ? — test: — commit: — perf: —
- [ ] V-0793 S-moqt-13.3-3 (draft-ietf-moq-transport-19) authorization tokens carried as message parameters must be verified by relays: tokens are expected to contain information about which actions/resources the presenting en
      ours: subscribe-flood — verdict: ? — test: — commit: — perf: —
- [ ] V-0794 S-moqt-13.3.1-1 (draft-ietf-moq-transport-19) replay of authorization tokens: replay protection for authorization tokens is the responsibility of the specific token sch
      ours: replay-attack — verdict: ? — test: — commit: — perf: —
- [ ] V-0795 S-moqt-13.4-1 (draft-ietf-moq-transport-19) relays can read and modify media objects absent end-to-end protection: media objects are accessible to relays and subject to both intentional and accidental modi
      ours: n-a-informational — verdict: ? — test: — commit: — perf: —
- [ ] V-0796 S-moqt-13.4-2 (draft-ietf-moq-transport-19) lack of source authenticity for media objects and properties: source authenticity, including authentication of some Track and Object Properties (e.g. ti
      ours: n-a-informational — verdict: ? — test: — commit: — perf: —
- [ ] V-0797 S-moqt-13.4-3 (draft-ietf-moq-transport-19) object sizes and traffic patterns enable content/correlation analysis by relays: n/a defense named beyond noting that end-to-end confidentiality mechanisms (external to th
      ours: object-size-abuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0798 S-moqt-13.4-4 (draft-ietf-moq-transport-19) end-to-end media security and key distribution are out of scope: end-to-end media security is handled by mechanisms external to this specification (e.g. an
      ours: n-a-informational — verdict: ? — test: — commit: — perf: —
- [ ] V-0799 S-moqt-parse-1 (draft-ietf-moq-transport-19) Key-Value-Pair Length field bounded to 2^16-1 bytes: the maximum length of a value is 2^16-1 bytes; if an endpoint receives a length larger tha
      ours: der-length-overflow — verdict: ? — test: — commit: — perf: —
- [ ] V-0800 S-moqt-parse-2 (draft-ietf-moq-transport-19) Reason Phrase Length bounded to 1024 bytes: the reason phrase length has a maximum value of 1024 bytes; if an endpoint receives a leng
      ours: der-length-overflow — verdict: ? — test: — commit: — perf: —
- [ ] V-0801 S-moqt-parse-3 (draft-ietf-moq-transport-19) Track Namespace field count and total length bounded: each Track Namespace Field Value MUST contain at least one byte; a Track Namespace with mo
      ours: object-size-abuse — verdict: ? — test: — commit: — perf: —
- [ ] V-0802 S-moqt-parse-4 (draft-ietf-moq-transport-19) AbsoluteRange Group ID arithmetic overflow bounded: if the resulting Group ID would be greater than 2^64 - 1, the endpoint MUST close the sess
      ours: der-length-overflow — verdict: ? — test: — commit: — perf: —

## IP / UDP / AF_XDP I/O

- [ ] V-0489 GHSA-px8v-pp82-rcvr (quic-go) path-mtu-spoofing: On Linux, an off-path attacker can inject spoofed ICMP 'Packet Too Big' / Fragmentation Needed messages to for
      ours: ICMP-derived PMTU update path (DPLPMTUD, RFC 8899) must validate the triggering packet against an in-flight probe before trusting the reported MTU — verdict: ? — test: — commit: — perf: —
- [ ] V-0490 GHSA-hxq4-mx37-fqvg (s2n-quic) nil-deref/crash-on-frame: Potential denial-of-service vulnerability in s2n-quic when receiving empty UDP packets.
      ours: UDP datagram ingestion path must handle a zero-length received datagram without crashing or looping — verdict: ? — test: — commit: — perf: —
- [ ] V-0491 CVE-2024-2169 (UDP application-layer protocol implementations generally (Loop DoS)) loop-dos: Loop DoS: crafted UDP packets with a spoofed source address can cause two servers running UDP-based applicatio
      ours: transport/io any UDP-based error/response path (e.g. QUIC stateless reset, VERSION_NEGOTIATION, or CONNECTION_CLOSE sent to an unvalidated address) must never trigger a symmetric error reply from the peer that could re-trigger our own error reply — rate-limit and never auto-respond to another error/reset packet — verdict: ? — test: — commit: — perf: —

## Media (mp4frag)

- [ ] V-0803 CVE-2016-3062 (FFmpeg (libavformat mov demuxer)) box-entry-count-overflow: mov_read_dref() in libavformat/mov.c mishandles the 'entries' count field of a dref box, allowing an out-of-bo
      ours: libavformat/mov.c mov_read_dref (dref box entry count) — verdict: ? — test: — commit: — perf: —
- [ ] V-0804 CVE-2015-1208 (FFmpeg (libavformat mov demuxer)) box-length-underflow: Integer underflow in mov_read_default() (the recursive ISOBMFF box-tree walker) allows disclosure of heap/stac
      ours: libavformat/mov.c mov_read_default (recursive box descent) — verdict: ? — test: — commit: — perf: —
- [ ] V-0805 CVE-2025-1373 (FFmpeg (libavformat mov demuxer)) missing-child-box-null-deref: mov_read_trak() dereferences a pointer that was never initialized when a malformed trak box tree omits an expe
      ours: libavformat/mov.c mov_read_trak (trak box child validation) — verdict: ? — test: — commit: — perf: —
- [ ] V-0806 CVE-2025-55648 (GPAC/MP4Box (isomedia)) sample-count-overflow: Heap-based buffer overflow in gf_opus_parse_packet_header() when the stsz (sample size) box entries for an Opu
      ours: gpac isomedia gf_opus_parse_packet_header (stsz-driven read) — verdict: ? — test: — commit: — perf: —
- [ ] V-0807 CVE-2025-55661 (GPAC/MP4Box (isomedia)) box-length-overflow: Heap-based buffer overflow in gf_opus_parse_packet_header() on a crafted MP4 with a malformed Opus packet payl
      ours: gpac isomedia gf_opus_parse_packet_header (Opus packet payload) — verdict: ? — test: — commit: — perf: —
- [ ] V-0808 CVE-2025-55652 (GPAC/MP4Box (isomedia)) box-length-overflow: Heap-based buffer overflow in gf_isom_vp_config_new() when parsing a crafted MP4 with a malformed VP codec con
      ours: gpac isomedia gf_isom_vp_config_new (vpcC box) — verdict: ? — test: — commit: — perf: —
- [ ] V-0809 CVE-2025-55641 (GPAC/MP4Box (isomedia)) sample-count-overflow: NULL pointer dereference in gf_isom_copy_sample_info() when Sample Auxiliary Information (SAI) metadata (e.g. 
      ours: gpac isomedia gf_isom_copy_sample_info (SAI sai_samples count) — verdict: ? — test: — commit: — perf: —
- [ ] V-0810 CVE-2025-55643 (GPAC/MP4Box (isomedia, DASH segmentation)) sample-count-overflow: NULL pointer dereference via TrackWriter handling when a crafted MP4 has malformed mvcC/stsz metadata during D
      ours: gpac isomedia TrackWriter / fragmented mp4 muxer (mvcC/stsz) — verdict: ? — test: — commit: — perf: —
- [ ] V-0811 TALOS-2021-1297 (GPAC (isomedia)) sample-count-overflow: Missing validation of entry counts in stco/stsc/stsz/stts/trun boxes allowed a size_t overflow when computing 
      ours: gpac isomedia stco/stsc/stsz/stts/trun entry-count validation — verdict: ? — test: — commit: — perf: —
- [ ] V-0812 CVE-2026-5235 (Bento4 (Ap4Dac4Atom / AP4_BitReader)) box-length-overflow: Heap-based buffer overflow in AP4_BitReader::ReadCache() within Ap4Dac4Atom.cpp: crafted MP4 dac4 box content 
      ours: Bento4 Ap4Dac4Atom.cpp AP4_BitReader::ReadCache — verdict: ? — test: — commit: — perf: —
- [ ] V-0813 CVE-2022-41428 (Bento4 (mp4mux, AP4_BitReader)) box-length-overflow: Heap overflow via AP4_BitReader::ReadBits() in Bento4's mp4mux tool triggered by a crafted MP4 file with bit-f
      ours: Bento4 AP4_BitReader::ReadBits (mp4mux) — verdict: ? — test: — commit: — perf: —
- [ ] V-0814 CVE-2017-14647 (Bento4 (Ap4SampleEntry.cpp)) box-length-overflow: Heap-based buffer overflow in AP4_VisualSampleEntry::ReadFields() (Core/Ap4SampleEntry.cpp) in Bento4 1.5.0-61
      ours: Bento4 Ap4SampleEntry.cpp AP4_VisualSampleEntry::ReadFields — verdict: ? — test: — commit: — perf: —
- [ ] V-0815 CVE-2017-14644 (Bento4 (AP4_HdlrAtom)) box-length-overflow: Heap-based buffer overflow in the AP4_HdlrAtom class parsing the hdlr box in Bento4 1.5.0-617, an out-of-bound
      ours: Bento4 AP4_HdlrAtom (hdlr box) — verdict: ? — test: — commit: — perf: —
- [ ] V-0816 CVE-2018-14325 (MP4v2 (mp4atom.cpp)) box-length-overflow: Integer underflow when parsing MP4Atom in mp4atom.cpp results in memory corruption via a crafted MP4 file with
      ours: mp4v2 mp4atom.cpp MP4Atom parsing — verdict: ? — test: — commit: — perf: —
- [ ] V-0817 CVE-2018-7339 (MP4v2 (mp4atom.cpp table property)) sample-count-overflow: MP4Atom class mishandles Entry Number validation for the MP4 Table Property (e.g. stsz/stco-style sample table
      ours: mp4v2 mp4atom.cpp table Entry Number validation — verdict: ? — test: — commit: — perf: —
- [ ] V-0818 CVE-2018-14326 (MP4v2 (mp4array.h, ftyp atom)) box-length-overflow: Integer overflow when resizing MP4Array for the ftyp atom results in memory corruption via a crafted MP4 file.
      ours: mp4v2 mp4array.h MP4Array resize (ftyp) — verdict: ? — test: — commit: — perf: —
- [ ] V-0819 CVE-2018-14446 (MP4v2 (atom_avcC.cpp)) box-length-overflow: MP4Integer32Property::Read() in atom_avcC.cpp allows a heap-based buffer overflow/DoS via a crafted avcC (AVC 
      ours: mp4v2 atom_avcC.cpp avcC box — verdict: ? — test: — commit: — perf: —
- [ ] V-0820 minimp4-issue-50 (minimp4 (MP4D_open)) sample-count-overflow: Heap buffer overflow via 32-bit integer overflow in malloc size calculations in MP4D_open(): sample_count*4 an
      ours: minimp4 MP4D_open (stsz/stts entry-count-derived malloc size) — verdict: ? — test: — commit: — perf: —
- [ ] V-0821 CVE-2011-1684 (VLC libmp4 (MP4_ReadBox_skcr)) box-length-overflow: Heap-based buffer overflow in MP4_ReadBox_skcr() in libmp4.c (VLC's MP4 demuxer) via a crafted MP4 file, allow
      ours: VLC libmp4.c MP4_ReadBox_skcr (skcr box) — verdict: ? — test: — commit: — perf: —
- [ ] V-0822 CVE-2019-11931 (WhatsApp (bundled MP4 elementary-stream metadata parser)) stack-overflow: Stack-based buffer overflow while parsing MP4 elementary-stream (elst-adjacent) metadata in a crafted MP4 file
      ours: WhatsApp bundled MP4 demuxer, elementary-stream metadata box parsing — verdict: ? — test: — commit: — perf: —
- [ ] V-0823 CVE-2022-1441 (GPAC/MP4Box (diST box)) box-length-overflow: diST_box_read() allocates a fixed-length buffer, but the content length actually read from the bitstream is at
      ours: gpac isomedia diST_box_read (diST box) — verdict: ? — test: — commit: — perf: —
- [ ] V-0824 L-mp4-0001 (ISO/IEC 14496-12 box size=0/si) box-length-overflow: 
      ours: box-length-overflow — verdict: ? — test: — commit: — perf: —
- [ ] V-0825 L-mp4-0002 (ISO/IEC 14496-12 nested box le) box-length-overflow: 
      ours: box-length-overflow — verdict: ? — test: — commit: — perf: —
- [ ] V-0826 L-mp4-0003 (ISO/IEC 14496-12 huge sample/e) box-length-overflow: 
      ours: box-length-overflow — verdict: ? — test: — commit: — perf: —
- [ ] V-0827 L-mp4-0004 (ISO/IEC 14496-12 fragmented-fi) box-length-overflow: 
      ours: box-length-overflow — verdict: ? — test: — commit: — perf: —

## Samples and dependencies (examples, frontend npm, e2e npm)

- [ ] V-0828 CVE-2026-69152 (brace-expansion@(see pnpm audit output)) regex-dos-incomplete-fix: brace-expansion DoS via unbounded intermediate arrays feeding combine(); the maxLength mitigation for CVE-2026
      ours: examples/moqt_chat/frontend — verdict: ? — test: — commit: — perf: —
- [ ] V-0829 GHSA-5p4m-2wfm-xmqj (js-yaml@(see pnpm audit output)) quadratic-cpu-dos: js-yaml quadratic CPU consumption when resolving !!omap in both the 3.x and 4.x branches; the fix for the rela
      ours: examples/moqt_chat/frontend — verdict: ? — test: — commit: — perf: —
- [ ] V-0830 CVE-2026-67213 (nanoid@(see pnpm audit output)) infinite-loop-dos: nanoid custom ID generators can loop indefinitely when called with size=0, causing a hang/DoS.
      ours: examples/moqt_chat/frontend — verdict: ? — test: — commit: — perf: —
- [ ] V-0831 CVE-2026-75604 (next@(see pnpm audit output)) rce: Next.js unauthenticated remote code execution specifically on Windows-hosted servers.
      ours: examples/moqt_chat/frontend — verdict: ? — test: — commit: — perf: —
- [ ] V-0832 CVE-2026-84373 (vitest / @vitest/mocker@(see pnpm audit output)) path-traversal: Vitest path traversal / arbitrary file read via @vitest/mocker's redirect-mock feature.
      ours: examples/moqt_chat/frontend — verdict: ? — test: — commit: — perf: —
- [ ] V-0833 GHSA-rgj7-g3m4-5g8c (sharp@(see pnpm audit output)) vendored-vulnerable-library: sharp bundles a libheif with known vulnerabilities (GHSA-g89c-p67h-r497, GHSA-2jg2-4ch7-h545).
      ours: examples/moqt_chat/frontend — verdict: ? — test: — commit: — perf: —
- [ ] V-0834 CVE-2026-84375 (js-yaml@(see pnpm audit output)) cpu-exhaustion-dos: js-yaml's maxTotalMergeKeys limit does not bound CPU usage for empty merge (<<:) sources, allowing a CPU-exhau
      ours: examples/moqt_chat/frontend — verdict: ? — test: — commit: — perf: —
- [ ] V-0835 GHSA-2xp9-vwfh-vxw4 (next@(see pnpm audit output)) rce: Next.js unauthenticated remote code execution in the built-in Image Optimization API when processing AVIF file
      ours: examples/moqt_chat/frontend — verdict: ? — test: — commit: — perf: —
- [ ] V-0836 GHSA-jmr9-qjv8-65gv (extract-zip (transitive via @puppeteer/browsers / puppeteer-core)) symlink-path-traversal: extract-zip allows an unvalidated symlink to traverse outside the target extraction directory (path traversal)
      ours: examples/moqt_chat/e2e — verdict: ? — test: — commit: — perf: —
- [ ] V-0837 GHSA-7pqw-9j4j-h8q3 (extract-zip (transitive via @puppeteer/browsers / puppeteer-core)) symlink-path-traversal: extract-zip allows arbitrary file writes outside the target directory through symlink archive entries in a cra
      ours: examples/moqt_chat/e2e — verdict: ? — test: — commit: — perf: —

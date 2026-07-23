[Docs](README.md) › Interop Results

# Interop Results

Interoperability runs against independent client implementations via the
[quic-interop-runner](https://github.com/quic-interop/quic-interop-runner).
This is the only evidence tier that proves wire compatibility: a
self-loopback test cannot catch a spec misreading shared by both ends.
Per-requirement unit/vector coverage lives in [Features](features/README.md).
Results as of 2026-07.

Legend: `✅` passed · `🟡` implemented but no verdict possible (peer/tooling
limitation, or a non-protocol gap) · `—` not demonstrated yet.

## QUIC testcases (server: wired · client: quic-go)

| Testcase | Implemented | Remark |
|---|---|---|
| `handshake` | ✅ | connection establishment |
| `transfer` | ✅ | file download over streams |
| `http3` | ✅ | parallel HTTP/3 GETs (3 streams, 500 KB bodies) |
| `longrtt` | ✅ | high-latency link |
| `chacha20` | ✅ | TLS_CHACHA20_POLY1305_SHA256 negotiation end to end, including a mid-transfer Key Update under that suite |
| `keyupdate` | ✅ | RFC 9001 §6 key update, both directions |
| `transferloss` | ✅ | file transfer under packet loss |
| `transfercorruption` | ✅ | file transfer under packet corruption |
| `amplificationlimit` | ✅ | RFC 9000 §8.1 anti-amplification enforced on an inflated (9-certificate) server flight |
| `goodput` (measurement) | ✅ | 10 MB in 11.5 s (~7.3 Mbps) over the runner's simulated link, repeatable |
| `blackhole` | ✅ | resumes correctly after a simulated 2 s link outage |
| `multiplexing` | 🟡 | MAX_STREAMS re-grant works correctly (verified live: the advertised limit climbs from 100 to 2000+ as requests complete, 98% of 1999 requested files finish), but the runner's fixed 60 s timeout for this case is not met; a pure throughput gap, not a functional one |
| `handshakeloss` | ✅ | all 50 handshakes complete under a 30% bursty loss rate. Three server-side gaps had to close: a boot-flight resend only replayed the still-unsent tail (one lost Handshake datagram deadlocked the handshake), the one-time confirmation packet (SETTINGS + ticket + HANDSHAKE_DONE) was never retransmitted when lost, and a still-incomplete split ClientHello was never acknowledged, starving the client's 5 s handshake idle timer |
| `handshakecorruption` | ✅ | same scenario under corruption; passes with the same fixes |
| `retry` | ✅ | RFC 9000 §8.1.2 forced address validation: a `--force-retry` server mode sends a Retry for every token-less Initial, verifies the presented token's HMAC (RFC 9000 §8.1.1) and address binding before accepting, and drops datagrams carrying an invalid one. The Retry Integrity Tag is pinned to the RFC 9001 Appendix A.4 vector. The wire token carries its embedded original DCID in the clear (`odcid_len \|\| odcid \|\| HMAC-SHA256`) so the server can statelessly recover it for `original_destination_connection_id`; the Initial-key derivation input (the Retry's own SCID) and that recovered original DCID are tracked as two distinct fields end to end so the TP advert is never mixed up with the key-derivation input |
| `resumption` | ✅ | PSK-based session resumption over a real second handshake, wired end to end into the ClientHello receive path and the server flight builder: `resumption_master_secret` spans the transcript through the *client's* Finished, not just the server's (RFC 8446 §7.1 -- this secret is the one exception among the four the key schedule derives, the other three stop at the server's own Finished); the ServerHello echoes `pre_shared_key` (`selected_identity`) whenever a PSK is accepted (RFC 8446 §4.1.3/§4.2.11); a PSK handshake omits Certificate/CertificateVerify entirely (RFC 8446 §4.4). Two consecutive real-interop runs pass; `handshake`/`transfer`/`retry`/`http3` all still pass (no regression) |
| `zerortt` | ✅ | 0-RTT data received and acted on, wired end to end, on top of resumption's PSK/key-schedule plumbing. 0-RTT datagrams that arrive before their packet-protection keys exist (which don't exist until the ClientHello finishes processing and the PSK is accepted) are buffered verbatim at the boot-accumulator layer and replayed once keys are derived (RFC 9001 §4.6.1). 0-RTT shares 1-RTT's App packet-number space (RFC 9000 §12.3) but keeps a long-header shape, so PN recovery branches on the header form instead of assuming every packet at that level is short-header. A response to a 0-RTT-carried request is deferred until the server's own 1-RTT send keys exist (the Finished-inclusive transcript). The concurrent-stream table is sized for the interop runner's 40-file zerortt burst (raised from a handful, same tradeoff already made for the WebTransport stream cap). Two consecutive real-interop runs pass; `handshake`/`transfer`/`retry`/`resumption`/`http3` all still pass |
| `ecn` | 🟡 | RFC 9000 §13.4 ECT(0) marking on send, IP_TOS cmsg reading on receive, and cumulative ECN counts reported in 1-RTT ACKs are all implemented and unit-tested, but the runner marks the case `?`: the quic-go interop client itself declares `unsupported test case: ecn`, so no end-to-end verdict is possible with this peer |
| `ipv6` | ✅ | transfer over native IPv6; the socket layer is dual-stack (one AF_INET6 socket, IPV6_V6ONLY off, IPv4 peers v4-mapped), so every other case still runs over IPv4 unchanged |
| `v2` | 🟡 | implemented and unit-proven end to end (key derivation, long-header type bits, and the Version Negotiation accept list are all version-parameterized; a v2-framed Initial carrying a real ClientHello is accepted and answered in v2), but no E2E verdict is possible: the quic-go interop client itself declares `unsupported test case: v2` (exit 127), same pattern as `ecn`. This server never actively switches a connection's version -- it replies in whichever version the client's own Initial arrived in (RFC 9368 2), rather than implementing the "server actively switches a v1-started connection to v2" behavior the runner's own TestCaseV2 check describes; whether that difference would matter for a client that actually exercises this case is unverified without one. Post-v2 regression run (handshake/transfer/http3/retry/ipv6) stayed all-green, confirming no impact on the v1 path |
| `rebind-port` / `rebind-addr` | — | the server follows a confirmed connection's peer address across a rebind and sends a PATH_CHALLENGE on the new path, validating a matching PATH_RESPONSE (RFC 9000 8.2/9.3). Manually decrypting the capture confirms the PATH_CHALLENGE is correctly the new path's first packet, but the runner's own analysis tooling (pyshark/tshark) cannot decrypt that same packet -- a short header carries no DCID length, and wireshark only learns it by having already seen an Initial/Handshake on that UDP conversation, which a rebind's fresh source port never provides. Believed to be a tooling-chain limitation rather than a protocol bug in this server |
| `connectionmigration` | 🟡 | run, but unverdictable for a different reason than rebind-port/addr: the server side works (the file transfer completes) and reuses the same PATH_CHALLENGE/PATH_RESPONSE machinery, but the quic-go client never actually triggers a path change for this testcase (runner log: "Server saw only a single path in use") -- a client limitation, not the tooling-chain decryption issue above |
| `crosstraffic` (measurement) | ✅ | 25 MB alongside a competing TCP cubic flow, 3269 (± 157) kbps across 5 runs, well above the 180 s completion bar |

## WebTransport testcases (server: wired · client: webtransport-go)

| Testcase | Implemented | Remark |
|---|---|---|
| `handshake` | ✅ | Extended CONNECT session establishment |
| `transfer-unidirectional-receive` | ✅ | server pushes files on uni streams |
| `transfer-bidirectional-receive` | ✅ | server replies on bidi streams |
| `transfer-datagram-receive` | ✅ | server pushes over DATAGRAMs |
| `transfer-unidirectional-send` | — | client upload stalls partway (QUIC-level flow control and ACKs verified correct on both sides via qlog; the client stops writing mid-transfer — under investigation) |
| `transfer-bidirectional-send` | — | same stall |
| `transfer-datagram-send` | — | same stall |

Two real interop bugs were found and fixed by these runs (a QPACK literal
field-line buffer split and a WebTransport stream-signal length bug), which
is exactly what this tier exists for.

## Honest summary of the gaps

- 5 of 22 QUIC interop testcases have not passed yet (both measurements
  have); only quic-go and webtransport-go have been used as peers.
- `ecn` and `v2` cannot get an end-to-end verdict from the current peer:
  the quic-go interop client itself refuses both testcases, so the
  implementations remain unit-tested only.
- `multiplexing` is functionally correct (verified live: the server raises
  its advertised stream limit as requests complete, and 98% of 1999
  concurrently requested files finish) but misses the interop runner's
  fixed 60 s timeout for this case -- a throughput gap, not a protocol one.
- `rebind-port` / `rebind-addr` implement the full RFC 9000 8.2/9.3
  PATH_CHALLENGE/PATH_RESPONSE round trip, and manually decrypting the
  capture confirms the server correctly sends a PATH_CHALLENGE as the new
  path's first packet. Both testcases still fail because the runner's own
  analysis tooling cannot decrypt that specific packet (a wireshark
  limitation around DCID-length inference on a fresh UDP conversation, not
  a protocol violation by this server). `connectionmigration` reuses the
  same machinery and was run: the server side works, but the quic-go
  client never actually triggers a path change for this testcase either
  (runner log: "Server saw only a single path in use") -- unverdictable
  for an unrelated reason (a client limitation).
- The three WebTransport `*-send` interop cases have never passed; the
  QUIC layer has been verified blameless via qlog, and the investigation
  is parked at the client's send scheduling.
- Ed25519 and RSA certificate paths, priorities (RFC 9218), version 2
  (RFC 9369), and QUIC-bit greasing (RFC 9287) are fully unit-tested but
  have never been exercised against a real peer.
- The AF_XDP path's self-built IPv4/UDP framing has no interop run.

---

**Next:** [Features](features/README.md) — per-spec EARS requirement
ledgers. ([all docs](README.md))

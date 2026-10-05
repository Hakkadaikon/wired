# Known Limitations

This page collects every known, deliberately accepted limitation of the wired
SDK (a libc-free C QUIC / HTTP/3 / WebTransport / MoQT stack) in one place, so a
reader does not have to piece it together from source comments, per-spec
ledgers and planning notes. Entries come from four places: the `ponytail:`
comments in `src/` (the repo's marker for a known, deliberately deferred
limitation), the "Not implemented" / "Out of scope" / `[ ]` items of the
per-spec ledgers in this directory, the MoQT multi-draft ledger and resume
notes under `tasks/`, and the BoringSSL vector skip tables. Each entry says what
is limited, who it affects, and where it is recorded. An entry marked
"(unverified)" was taken from a hand-off note and not re-checked against the
code when this page was written.

Last reviewed: 2026-10-05

Source shorthand: `L<n>` = `tasks/moqt-multidraft-ledger.md` item `<n>` (e.g.
`L12-3` is item 12-3); `RESUME` = `tasks/moqt-multidraft-RESUME.md`;
`ledger:<file>` = a file in this directory; `file:line` = a `ponytail:` comment
or definition in the tree at the review date (line numbers drift, grep the
quoted name if a line has moved).

Contents: [MoQT relay (hub)](#moqt-relay-hub) |
[MoQT versions and spec deviations](#moqt-versions-and-spec-deviations) |
[Raw-QUIC MoQT](#raw-quic-moqt) | [WebTransport](#webtransport) |
[HTTP/3 and QPACK](#http3-and-qpack) | [QUIC transport](#quic-transport) |
[TLS 1.3](#tls-13) | [Cryptography](#cryptography) |
[Platform / I/O](#platform--io) | [Capacity limits](#capacity-limits) |
[Testing and verification gaps](#testing-and-verification-gaps) |
[Out of scope by design](#out-of-scope-by-design)

---

## MoQT relay (hub)

The hub (`src/app/moqt/run/`) is a single-process, room-sized relay, not a
general relay network.

- **One announcer per name** — the hub keys one track per Full Track Name, so
  a second publisher announcing the same name is not tracked separately (9.5
  says "each publisher"). Impact: federations of publishers for one track.
  Source: `src/app/moqt/run/moqtrun.c:8359` (ponytail), L12-3.
- **Announcements after establishment ignored** — once an upstream SUBSCRIBE
  (hub to publisher, d18/19 9.4, d22 7.4) is Established, a later announce for
  that name is ignored. Source: L12-3 ("known limitations").
- **Publisher RESET of the hub's upstream stream not handled** — if the
  publisher resets the stream the hub opened for its upstream SUBSCRIBE, the
  hub does nothing until the session ends. Source: `moqtrun.c:8359`, L12-3.
- **SUBGROUP before SUBSCRIBE_OK dropped** — a SUBGROUP stream that reaches the
  hub before the upstream SUBSCRIBE_OK is dropped, not buffered (unverified;
  from the hand-off brief, no code comment found). Impact: first Objects of a
  publisher that races its own SUBSCRIBE_OK. Source: L12-3 area.
- **PUBLISH_DONE relay: header-only upstream stream not counted** — an
  upstream stream that carried only a SUBGROUP header plus FIN is never
  resolved to a track and is not counted against the publisher's Stream Count;
  the wait is absorbed by the 2 s cap (`WIRED_MOQTRUN_PUBDONE_WAIT_MS`, then
  remaining streams are reset). Impact: a delayed PUBLISH_DONE of up to 2 s.
  Source: L12-2, `moqtrun.h:707`.
- **Start-Object granularity (4-15)** — Location Filters are Group-granular on
  the start side: Objects of the start Group below the start Object still pass
  on a multi-Object stream. The End side is cut per Object (d22 End Object),
  but only on the lossy path. Source: `moqtrun.c:1464` (ponytail), L4-15.
- **Reliable ring path: no End Object cut, stream-granular start** — the
  ring-backed (reliable) relay gates by Group only: it does not cut at a
  draft-22 End Object mid-round, and a stream that began before a
  subscription's start is not sent to it even for later Objects (chat sends one
  Object per stream so loses nothing). Source: `moqtrun.c:6260`, `moqtrun.c:5881`,
  L4-15.
- **Subscriber-less ring holds its publisher** — a ring no cursor has joined
  may hold the publisher up to `WIRED_MOQTREL_STALL_MS` (10000 ms). Source:
  `moqtrun.c:6155`.
- **Ring arrival marks absorb appends** — with all `WIRED_MOQTREL_MARKS` (8)
  taken, the newest mark absorbs further appends, so a delivery timeout can
  fire early by at most the time since that mark. Source: `moqtrel.h:134`.
- **Fill fetch: track claim does not reset fills** — `moqtrun_track_claim`
  resets orphaned relay streams but does not reset in-flight fill (FILL_PARAMETERS)
  streams of the previous incarnation (unverified; from the hand-off brief).
  Source: `moqtrun.c:783`, L4-6 / L12-16.
- **Fill / FETCH capacity refusal** — fills beyond `fetches[]` + `fetch_waits[]`
  (8 + 8) are refused REQUEST_ERROR INTERNAL_ERROR before the OK is sent (the
  earlier silent drop was fixed in L12-16). Source: `moqtrun.c:2838`, L12-16.
- **No upstream FETCH** — the hub never forwards a FETCH to another relay
  (no FETCH-of-FETCH); fills and Joining FETCH are served from its own cache
  only, and a d22 Joining FETCH is refused. Impact: MQ22-137 has no code path.
  Source: L4-13, L4-6, `ledger:draft-moq-transport-22.md` MQ22-137.
- **Descending FETCH gap rules** — a
  Descending FETCH is served newest group first, but d22's descending-order gap
  rules (3.2.2) are not implemented. Source: `ledger:draft-moq-transport-22.md`
  Not implemented (SS9.11, SS3.2.2).
- **Object cache is arena-scanned** — eviction compacts the arena with one
  memmove pass and lookups scan linearly (O(arena) per call, also per
  FETCH_OK); groups are assumed to arrive in ascending order per track, so an
  older-group Object is cached as if new. Arena is app-supplied; max cached
  payload `MOQCACHE_OBJ_MAX` (65472). Source: `src/app/moqt/cache/moqcache.h:23`,
  `moqtrun.c:2661`.
- **Discovery syncs are quadratic** — SUBSCRIBE_NAMESPACE catch-up is an
  O(reqs^2) scan per event and SUBSCRIBE_TRACKS sync is O(sessions x tracks x
  reqs); fine at the fixed capacities. Source: `moqtrun.c:4074`, `moqtrun.c:4446`.
- **Subgroup / priority / property filter rows pass** — SUBGROUP_FILTER,
  PRIORITY_FILTER, OBJECT_PROPERTY_FILTER and TRACK_PROPERTY_FILTER rows are
  validated and stored but not evaluated at delivery (the Group-granular gates
  never see those fields). OBJECTID_FILTER gates datagrams only. Source:
  `moqtrun.h:300` (ponytail), `ledger:draft-moq-transport-22.md` Out of scope.
- **No Alias token cache** — the hub does not advertise
  MAX_AUTH_TOKEN_CACHE_SIZE; Token Aliases are refused. A REGISTER should
  terminate the session with AUTH_TOKEN_CACHE_OVERFLOW (10.2.2) but the hub has
  no session-close io there, so it refuses the request. Source: `moqtrun.c:2081`.
- **DEFAULT_PUBLISHER_PRIORITY property not read** — an omitted Publisher
  Priority is always 128 (12.4 Track Property not parsed). Source: `moqtrun.c:5214`.
- **OBJECT_DELIVERY_TIMEOUT start point is "leading byte of the Object"** —
  d19 ("first payload byte") and d22 ("last header byte") collapse to the same
  moment because Objects decode atomically. Source: `moqtrun.c:5676`, L4-11,
  `ledger:draft-moq-transport-22.md` MQ22-070a (`[ ]`).
- **Track Name truncated at 64 bytes** — `moqtrun_record_track_name` truncates
  to `WIRED_MOQTRUN_MAX_NAME` instead of rejecting. Source: `moqtrun.c:523`.
- **Priorities scheduling** — only Subscriber Priority is applied (as
  WebTransport stream urgency); Publisher Priority scheduling, fill-vs-live
  tie-break and the across-subscriptions algorithm are not implemented. Source:
  `ledger:draft-moq-transport{,-18,-22}.md` Out of scope (SS7 / SS5).
- **One publisher per Track** — several publishers may share a namespace, but
  each Track still has one; no aggregation/deduplication across publishers
  (d19 9.3, d22 7.4). Source: ledgers, Out of scope.
- **Properties are opaque** — MAX_CACHE_DURATION, DEFAULT_PUBLISHER_GROUP_ORDER,
  DYNAMIC_GROUPS, Immutable Properties, Prior Group/Object ID Gap (and d22's
  TIMESTAMP, VIDEO_FRAME_MARKING, AUDIO_CONFIG, ENCRYPTED_LIST, PADDING) are
  relayed unchanged, never interpreted. Source: ledgers, Out of scope.
- **FILL_TIMEOUT, EXPIRES, NEW_GROUP_REQUEST decoded, not acted on**;
  FILL_TIMEOUT's presence only gates the Timed-Out marker (d22). Source:
  ledgers, Out of scope. (RENDEZVOUS_TIMEOUT is acted on since L12-1; the
  ledger text still lists it as decoded-only and is stale on that point.)
- **INCLUDE_PROPERTIES (0x35, d22 9.20.21) not decoded** — MQ22-083a is `[ ]`.
  Source: `ledger:draft-moq-transport-22.md`.
- **Padding Datagrams not sent**. Source: ledgers (SS11.5).
- **No Session Migration / REDIRECT behavior** — the hub never sends REDIRECT
  and does not react to one; there is no upstream relay or sibling to move a
  requester to. Source: L4-12, ledgers.
- **PUBLISH_DONE on the legacy control stream** — a subscription made on the
  legacy (control-stream) path gets no PUBLISH_DONE (no request stream); it is
  kept for a publisher rejoin. Source: ledgers, Not implemented.
- **REQUEST_UPDATE of a SUBSCRIBE_TRACKS** — answered REQUEST_ERROR
  NOT_SUPPORTED (request stays established). Source: ledgers, Not implemented.
- **Malformed-Track detection is minimal** — only unknown Object Status and
  Object ID overflow are checked at decode; the general receiver-side catalog
  (priority mismatch across a Subgroup, differing finals, duplicate Objects
  with different payload, ...) is not implemented. Source: ledgers (SS2.4.2 /
  SS12.1).
- **Object-Property delivery-timeout on datagrams (d18)** — MQ18-118a (ruling
  Q18-05, close PROTOCOL_VIOLATION) has no code path or test. Source:
  `ledger:draft-moq-transport-18.md` MQ18-118a (`[ ]`).
- **Per-Location-Filter end does not end the subscription** — d22 behaviour is
  intended and implemented for every version, but MQ22-108b / 137a have no
  dedicated test. Source: `ledger:draft-moq-transport-22.md`.
- **Duplicate-filter check keys on type only** — the duplicate-parameter check
  (`moqctl_param_dup`, `src/app/moqt/ctl/moqctl.c:524-535`) compares type, not
  (type, SetID), so two Range Filters of one type with different SetIDs are
  not distinguished. Source: ledger note at `tasks/moqt-multidraft-ledger.md:335`.
- **Drained session grace is fixed** — `WIRED_MOQTRUN_GOAWAY_GRACE_MS` (1000 ms)
  between PUBLISH_DONE flush and GOAWAY_TIMEOUT close; not an ack wait. Source:
  `moqtrun.h:697`.

## MoQT versions and spec deviations

- **Supported drafts: 18, 19, 22 only** — draft-14 to -17 and drafts 20/21 are
  out of scope (different control-stream shape / varint); ALPN `moq-00` also
  unsupported. Source: L9-1, `tasks/moqt-multidraft-ledger.md:282`.
- **Deliberate deviation: Filter Type 250 accepted as Largest Object** —
  moxygen sends its own, non-spec Filter Type 250 (LargestGroup); the hub treats
  it as Largest Object (`moqctl_locfilter_is_quirk`) instead of closing with
  PROTOCOL_VIOLATION. Revert the branch for strict compliance. Impact: a
  strict peer sending 250 expecting rejection. Source: commit `b217989`,
  `src/app/moqt/ctl/moqctl.c:995`, `tasks/moqt-multidraft-ledger.md:387`, RESUME.
- **Deliberate deviation: rendezvous hold capped at 1.5 s** —
  `WIRED_MOQTRUN_RDV_MAX_MS` is 1500 because imquic sends 500000 (microseconds)
  where milliseconds are expected and gives up after 2 s; a legitimate
  rendezvous wait longer than 1.5 s ends with REQUEST_ERROR TIMEOUT (the draft
  lets a relay use a shorter timeout, 10.2.6). Source: commit `03e69af`,
  `moqtrun.h:615`, L12-1.
- **Deliberate deviation: unknown PSK identity aborts** — see
  [TLS 1.3](#tls-13) (RFC 8446 4.2.11).
- **MAX_REQUEST_UPDATES credit gated by version** — a draft-18 peer is never
  closed for too many REQUEST_UPDATEs (the limit does not exist in d18). Not a
  gap, recorded for completeness. Source: L12-5.
- **Range Filters do not exist in draft-18** — the hub closes a d18 session
  that sends one (unknown parameter type). Source: ledger:draft-moq-transport-18.md.

## Raw-QUIC MoQT

Native QUIC ALPN `moqt-18/19/22` shares the hub with WebTransport
(`wired_moqt_on_session_raw`). All of it is verified in-process plus pinned
xquic/moqtopus bytes; see [Testing](#testing-and-verification-gaps).

- **raw_policy accepts every well-formed PATH/AUTHORITY** — the hub's
  `raw_policy` (`moqraw_accept_all`) validates only RFC 3986 shape
  (MALFORMED_PATH 0x9 / MALFORMED_AUTHORITY 0x1A); any well-formed value is
  accepted unless the app installs a hook. Source: `src/app/moqt/qraw/moqraw.c:145`,
  L13-7.
- **GOAWAY New Session URI is empty on raw QUIC** — the app's one URI names the
  WebTransport endpoint, so raw sessions send an empty URI ("reuse the current
  one"). Re-open condition: a mixed deployment that must hand a https:// WT
  client a different target. Source: `moqtrun.c:8151`, `moqtrun.h:1176`, L13
  "対象外".
- **0-RTT refused on a raw ALPN** — a raw-QUIC connection is never admitted in
  0-RTT (d18 3.3.1 / d22 6.3.1 relay MAY). Re-open condition: a peer that
  demands 0-RTT. Source: L13-3, L13 "対象外".
- **Close reasons cut to 48 bytes** — the hub's application CONNECTION_CLOSE
  (0x1d) reason phrase is truncated (at a UTF-8 boundary) to
  `SRVRUN_RAW_CLOSE_REASON_MAX` = 48. Source: `srvrun.c:3830`.
- **9 client uni streams on raw** — one uni stream per MoQT subgroup; the
  advertised uni limit is 9 and each backed slot costs one
  `WIRED_SRVLOOP_WT_BUF_CAP` window (`WIRED_SRVLOOP_MAX_WT_UNI_STREAMS` = 9). An
  HTTP/3 client gets 6 of them for WT data. Source: `srvloop.h:369`.
- **Hub full on raw** — with no free peer slot a raw session is closed
  INTERNAL_ERROR. Source: `moqtrun.h:1176`, L13-9.
- **No raw MoQT client role** — wired has no raw-QUIC MoQT client; only the
  relay role is registered in the interop runner. Source: L13 "対象外".
- **`moqt://` URI scheme and resolution** — URI parsing, SVCB/HTTPS RR and
  dereferencing are client concerns and not implemented. Source: ledgers.
- **Real-peer verification partial** — raw-QUIC relay `wired-quic` passes 13/14
  with every client that supports the transport; the remaining 1 is a
  client-transport mismatch, not a wired failure. Source: RESUME.

## WebTransport

- **Connection teardown approximates session termination** — srvrun frees a
  connection's WT sessions on peer CONNECTION_CLOSE, boot failure or idle sweep,
  while a CONNECT stream's own RESET/FIN is now handled per session (SS4.4,
  `srvrun.c:3352`). The `ponytail:` at `srvrun.c:5940` predates that trigger;
  the approximation is the fallback for whole-connection teardown. Source:
  `srvrun.c:5940`.
- **One latched reset per step** — only the last WT stream reset seen in one
  server step is delivered to the app and its slot freed; an earlier one in the
  same step is lost. Rapid-reset detection (RFC 9114 10.5) still counts every
  frame. Accepted (YAGNI). Source: `srvloop/dispatch.c:864`, L6-7.
- **WT receive buffers drop or truncate overflow** — a write outside the
  granted window of a WT bidi/uni slot is dropped; the `req_buf` / control
  buffer overflow is truncated. Source: `srvloop.h:141`, `srvloop.h:201`,
  `srvloop.h:311`, `srvloop.h:411`.
- **Out-of-order gap ranges** — a WT stream tracks at most
  `WIRED_SRVLOOP_WT_MAX_RANGES` (8) disjoint gaps in one window; more are
  coalesced or dropped (not reachable at targeted sizes). Source:
  `srvloop.c:647`.
- **Only one pending outbound datagram per connection** — the WT datagram
  send queue is single-slot, last-writer-wins (`dg_pending_buf[1200]`). Source:
  `srvrun.c:598`, `srvrun.c:4387`.
- **Pre-establishment datagram buffering is truncated** —
  `WIRED_WT_MAX_BUFFERED_DATAGRAMS` (4) datagrams of up to
  `WIRED_WT_BUFFERED_DATAGRAM_CAP` (256) bytes; longer ones are truncated, not
  dropped. Source: `src/app/webtransport/session/session/session.h:52`.
- **Datagram drain is a fixed slice, not congestion-controlled** —
  `SRVRUN_DGRING_DRAIN_MAX` 16 / `_MS` 5 / `_BYTES` 3000 (about 4.8 Mbps).
  Source: `srvrun.c:5670`.
- **A capsule-only connection never re-grows MAX_DATA** — a connection carrying
  only capsules (no WT stream, no streamed body) keeps the initial 10 MB
  (`STP_DEFAULT_MAX_DATA`) of connection credit. Source: `srvrun.c:3299`.
- **Concurrent WT sessions per connection** — `SRVRUN_MAX_WT_SESSIONS` (2)
  with a global cap `WIRED_CONNTABLE_CAP` and `SRVRUN_MAX_WT_SESSIONS_PER_WINDOW`
  (10). Source: `srvrun.c:181`, `srvrun.c:198`, `srvrun.c:218`.
- **Flow-control capsules ignored when WT flow control is off** — intended
  (draft-16 5.1, L6-8); listed so callers know that enabling it is a SETTINGS
  decision. Source: L6-8.
- **Server-initiated stream blocked: caller retries** — the open function
  returns -1 and WT_STREAMS_BLOCKED is sent only for the stream-count cause;
  retry is the caller's. Source: L6-10.
- **No HTTP/2 / capsule-only WebTransport** and no rate-limit headers or
  intermediary flow-control re-expression. Source:
  `ledger:draft-webtrans-http3.md` Out of scope.
- **`h3_tunnel_relay` only flips state** — the CONNECT tunnel's raw byte relay
  is the application's job (over h3 DATA frames). Source:
  `src/app/http3/core/h3/connect.c:63`.
- **Capsule-Protocol header not generated or parsed** (RFC 9297 3.4) — not
  required by WebTransport; a deliberate scope decision. Source:
  `ledger:rfc9297.md` Out of scope.
- **Capsule-only HTTP Datagram fallback absent** — QUIC DATAGRAM is assumed.
  Source: `ledger:rfc9297.md`.

## HTTP/3 and QPACK

- **Origin server only** — no CONNECT proxying to TCP (only Extended CONNECT per
  RFC 9220), no server push (PUSH_PROMISE, push-ID priority), no client role
  behaviours. Source: `ledger:rfc9114.md`, `ledger:rfc9218.md`,
  `ledger:rfc9220.md`.
- **QPACK dynamic table disabled** — the decoder advertises capacity 0 and the
  encoder emits only Required-Insert-Count-0 sections; the server sends no
  QPACK instructions. Impact: headers are not compressed across requests.
  String encoding always H=0 (no Huffman on output). Source: `ledger:rfc9204.md`,
  `ledger:rfc7541.md` Out of scope.
- **HTTP semantics are the application's** — no trailers, `Date`, conditional
  or range requests, content negotiation, TRACE; field values are passed
  verbatim. Source: `ledger:rfc9110.md` Out of scope.
- **Response body cap** — fixed grid rows hold
  `WIRED_SRVRUN_RESP_MAX` (16384) minus header room (15872 body bytes);
  larger bodies use a `srvbigbuf` row or streaming. 64 conns x 4 slots is about
  4 MB BSS, multiplied by worker count under `--cores N`. Source:
  `srvrun.c:907`; handler body cap `WIRED_SRVLOOP_BODY_MAX` 1024. Source:
  `srvloop/respond.c:272`.
- **Request buffer limited to `BODYWIN_CAP` (2048)** — overflow is truncated,
  and a request filling exactly one window with its FIN in a later empty frame
  is answered as "window stuck". Control stream buffer
  `WIRED_SRVLOOP_CTRL_BUF_CAP` 512. Source: `srvloop.h:141`, `dispatch.c:1340`.
- **Refusal queue drops silently when full** — a full refusal queue drops the
  refusal; the stream stays open. Source: `srvloop/srvloop.c:553`.
- **Lost RESET_STREAM/STOP_SENDING may not be retransmitted** — `srvrun_rst_keep`: a full
  table or oversize payload is sent once but never retransmitted
  (RFC 9000 13.3). Source: `srvrun.c:1944`.
- **Peer STOP_SENDING answered with FIN, not RESET_STREAM** — when the peer sends STOP_SENDING on a server response stream, srvrun
  answers with FIN rather than RESET_STREAM, because dispatch latches a
  stream-close without distinguishing FIN, RESET_STREAM and STOP_SENDING
  (unverified end-to-end; from the hand-off brief). Impact: a client that sent
  STOP_SENDING sees a clean end instead of an error code. Source:
  `src/app/http3/server/srvloop/dispatch.c:929` (`is_close_shaped`),
  `srvrun.c:3352`.
- **Graceful shutdown is tick-bounded** — GOAWAY then at most
  `SRVRUN_DRAIN_TICKS` (25) x 200 ms (about 5 s) before close; a SIGTERM before
  the handler is installed takes the default action (no GOAWAY). Source:
  `srvrun.c:10245`, `srvrun.h:277`.
- **Worker supervisor wakes every 100 ms** — idle wakeups and up to 100 ms
  SIGTERM-forward latency (no signalfd); SO_REUSEPORT wiring lives in srvrun's
  listen path. Source: `srvworkers/srvworkers.c:188`, `srvworkers.h:13`.
- **Spin backoff is count-based** — no time-based backoff (the only clock is
  millisecond-granular). Source: `srvpoll/srvpoll.c:11`.
- **Receive batch** — `SRVRUN_RX_BATCH` (16) datagrams per recvmmsg, 32 KB per
  env. Source: `srvrun.c:1033`.
- **Idle timeout and eviction grace fixed** — `WIRED_SRVRUN_IDLE_MS` 30000,
  `WIRED_SRVRUN_EVICT_GRACE_MS` 1000. Source: `srvrun.c:5995`, `srvrun.c:9908`.

## QUIC transport

- **Retry token key is fixed** — `g_srvrun_retry_key`: one process-lifetime
  HMAC key, no rotation (same policy as the ticket key). Source:
  `srvrun.c:9760`.
- **Preferred-address migration is one-way sticky** — once on the
  preferred-address socket, old-path stragglers cannot flip a connection back;
  there is no general per-path highest-packet-number tracking. Source:
  `srvrun.c:9425`.
- **ECN marking is socket-wide** — ECT(0) is set with a socket-wide `IP_TOS`,
  so a failed validation only stops consuming reports; it cannot unmark one
  connection. ECT(1) is never sent. Source: `srvrun.c:8438`, `udp.h:183`.
- **No kernel-fallback paths for socket options** — `IP_TOS`/`IP_RECVTOS`,
  `IP_MTU_DISCOVER`-style PMTU probe options propagate setsockopt errors; there
  is no degraded non-ECN or non-probe path. Source: `src/transport/io/socket/io/udp.h:183`,
  `:197`, `:209`.
- **Time-threshold loss detection is off in the connrunner loop** —
  `CONNRUNNER_NO_RTT_DELAY` makes detection purely packet-threshold (RFC 9002
  6.1.1) there. The server path (srvrun) uses its own recovery. Source:
  `src/transport/conn/loop/connrunner/send.c:117`.
- **`connio` sends always mark ack-eliciting** — hard-set to 1; a
  non-eliciting-only send is not classified. Source:
  `src/transport/conn/loop/connio/connio.c:64`.
- **`appdata_recv` has no packet-number history** — the one-shot entry passes
  largest_pn 0; full-PN recovery is the srvloop path's job. Source:
  `src/transport/stream/data/appdata/app_recv.c:9`.
- **HyStart++ CSS phase folded into direct exit** — more conservative; a
  spurious exit costs earlier congestion avoidance. Source:
  `src/transport/recovery/congestion/cc/hystart.h:10`.
- **Key Update limit stalls instead of closing** — a confidentiality limit hit
  while the previous update is unconfirmed stalls sends (idle timeout first
  in practice). Source: `srvloop/send.c:109`.
- **Linear connection table** — `WIRED_CONNTABLE_CAP` 64 slots, linear scan.
  Source: `conntable.h:13`.
- **0-RTT replay ring** — `ZERORTT_SEEN_CAP` 4096 fingerprints, oldest evicted;
  no persistence or cross-process sharing. Replay of an evicted entry is
  bounded by the ticket lifetime. Source: `zerortt_seen.h:12`.
- **PTB (ICMP) ignored** — DPLPMTUD is probe-based only (RFC 8899 4.6.1
  option); fixed 1200-byte maximum datagram for the initial window; no
  PLPMTU sharing across flows; no ERROR/DISABLED phases. Source:
  `ledger:rfc8899.md`, `ledger:rfc9000.md`, `ledger:rfc9002.md` Out of scope.
- **Optional RFC 9002 heuristics not implemented** — min_rtt re-establishment,
  RTT reuse across connections, loss leniency for pre-key packets, RFC 7661
  window update, CE-marking probe. Source: `ledger:rfc9002.md` Out of scope.
- **IPv4/UDP/IP details** — no IP options, fragmentation/reassembly, ToS use,
  TTL fixed 64 on the AF_XDP path; UDP source port 0 case not handled. Source:
  `ledger:rfc791.md`, `ledger:rfc768.md` Out of scope.
- **Connection migration interop** — the 2026-10-04 interop run showed
  `connectionmigration` failing with many clients (older run; current status
  not re-measured here, unverified). `ecn` and `v2` testcases are unsupported
  by several clients. Source: `tasks/moqt-multidraft-ledger.md:254` (run
  37219504844).
- **Client-side behaviours not shipped** — client packet handling, Version
  Negotiation reaction, 0-RTT client rules; the server ignores received
  Version Negotiation packets. Source: `ledger:rfc9000.md`, `ledger:rfc9368.md`,
  `ledger:rfc9369.md`, `ledger:rfc8999.md` Out of scope.

## TLS 1.3

- **Unknown PSK identity aborts the handshake** — a PSK identity that cannot be
  opened (e.g. after the ticket key rotated) aborts with decrypt_error,
  indistinguishable from a bad binder (E.6), instead of falling back to a full
  handshake (RFC 8446 4.2.11 SHOULD). Impact: a client must retry without its
  ticket. Add a keyed dummy-open plus fallback if that bites. Source:
  `src/tls/handshake/core/sdrv/sdrv.c:683`, `ledger:rfc8446.md` 8446-053
  (`[ ]`), `tasks/moqt-multidraft-ledger.md:374`.
- **Ticket key fixed for the process lifetime** — session tickets are sealed
  under one fixed key, no rotation, no multi-key acceptance. Impact: a leaked
  key exposes every ticket ever issued. Source:
  `src/app/http3/server/srvloop/respond.c:80`.
- **No `ticket_nonce` in NewSessionTicket** — a real client needs a per-ticket
  nonce for multi-ticket PSK selection; none is emitted. Source:
  `src/tls/handshake/core/tls/newsessionticket.h:16`.
- **Ticket replay guard is a ring** — `TICKETGUARD_CAP` (64) fingerprints; an
  entry evicted by newer tickets could replay past the window. Source:
  `src/tls/keys/ticketguard/ticketguard.h:12`.
- **Cipher suites: AES-128-GCM-SHA256 and ChaCha20-Poly1305-SHA256 only** —
  `TLS_AES_256_GCM_SHA384` is rejected by `cipher_supported`. Impact: a peer
  that offers only AES-256 fails to negotiate. Source:
  `src/tls/handshake/core/tls/cipher.c:3`, `ledger:fips197.md` Out of scope.
- **No client authentication or server-side CertificateRequest** — the server
  never requests client certificates (codec exists unwired); no
  post_handshake_auth, no OCSP/SCT, no `certificate_authorities` selection, no
  FFDHE; external PSKs ("ext binder") unsupported. Source:
  `ledger:rfc8446.md` Out of scope.
- **TLS extensions not shipped** — max_fragment_length, client_certificate_url,
  trusted_ca_keys, truncated_hmac, status_request. Source: `ledger:rfc6066.md`.
- **ClientHello and Retry scratch buffers are MTU-bounded** — the
  boot-stage accumulator is ~4 KB per slot (64 slots, BSS) and spans two
  Initials; `retry_tag` pseudo-packet scratch is 1521 bytes. Source:
  `srvrun.c:488`, `src/tls/handshake/core/tls/retry_tag.c:24`.
- **Client / server pump shortcuts** — `wired_server_feed` and
  `client_build_initial` carry the handshake payload without on-wire AEAD
  Initial protection in those legacy entry points; real protection goes through
  connio. Source: `src/tls/handshake/roles/server/serverio.c:5`,
  `src/tls/handshake/roles/client/client.c:45`.
- **Certificate path processing** — iPAddress name-constraint subtrees are not
  applied to an IP-literal CN; no CRL / OCSP / revocation, policy mappings,
  IDN processing, SRV-ID/URI-ID matching (only DNS-ID dNSName). Source:
  `src/crypto/pki/encoding/x509/nameconstraints.c:337`, `ledger:rfc5280.md`,
  `ledger:rfc6125.md` Out of scope.
- **Signature algorithms in chains** — chains signed with P-521,
  ECDSA-with-SHA-512 or legacy RSA-SHA-1 cannot be verified. Source:
  `tests/vectors/boringssl/README.md`.

## Cryptography

- **Hash / MAC set** — SHA-256, SHA-384 and SHA-512 shipped; **not** SHA-1,
  SHA-224, SHA-512/224, SHA-512/256, MD5. HMAC-SHA256 and HMAC-SHA384 only:
  **no HMAC-SHA512, HMAC-SHA1, HMAC-SHA224, HMAC-MD5**; HKDF is SHA-256 only
  in the TLS/QUIC profile. SHA-512 therefore has no third-party vector.
  Impact: none for TLS 1.3 handshakes; certificate chains signed with
  SHA-512-based or SHA-1 algorithms cannot be verified. Source:
  `docs/security/boringssl-vectors.md`, `tests/vectors/boringssl/README.md`,
  `ledger:fips180-4.md`, `ledger:rfc5869.md`, RESUME.
- **Curves: P-256 and P-384 only** — **no P-224, P-521, secp224k1, P-192,
  binary or Koblitz curves**; P-384 is verify-only (certificate chains), P-256
  signs (deterministic RFC 6979, `ecdsa_secp256r1_sha256` only). 179 BoringSSL
  ECDSA vectors skipped for this reason. Source: same as above,
  `ledger:rfc6979.md`, `ledger:rfc5480.md`.
- **No X448 / Ed448 / Ed25519ctx / Ed25519ph**; X25519 and pure Ed25519 only;
  Ed25519 has no PKCS#8/OneAsymmetricKey parsing (raw 32-byte seed) and DER
  only (no BER). Source: `ledger:rfc7748.md`, `ledger:rfc8032.md`,
  `ledger:rfc8410.md`.
- **AEAD: 96-bit nonce and 128-bit tag only** — `GCM_NONCE` is 12 bytes and
  `GCM_TAG` 16; BoringSSL AES-GCM cases with other nonce lengths (5 in
  AES-128, 2 in AES-256) are skipped; no GMAC; short tags unsupported. Impact:
  none for QUIC/TLS 1.3. Source: `docs/security/boringssl-vectors.md`,
  `ledger:sp800-38d.md`.
- **AES-128 is the QUIC primitive; AES-192 not implemented** — AES-256-GCM
  exists as a primitive (`gcm256.h`, BoringSSL vectors pass) but no TLS cipher
  suite uses it; no AES-192; no AES decryption primitive (not needed by GCM or
  header protection). Source: `ledger:fips197.md`,
  `docs/security/boringssl-vectors.md`.
- **RSA: public exponent e = 65537 only; verify only** — PKCS#1 v1.5 verify
  accepts SHA-256/384/512 DigestInfo; RSA-PSS is SHA-256 with salt length 32
  and MGF1-SHA-256 only (TLS 1.3 `rsa_pss_rsae_sha256`). No RSA signing,
  encryption, key generation or private-key type. No BoringSSL RSA vectors.
  Source: `src/crypto/asymmetric/rsa/rsa_verify.h:12`,
  `src/crypto/asymmetric/rsa/pss.c:6`, `ledger:rfc8017.md`.
- **ECDSA/ECC key generation not shipped** — keys are loaded from
  certificates/PEM; no DSA at all. Source: `ledger:fips186-4.md`.
- **Fixed scratch sizes** — ChaCha20-Poly1305 MAC scratch is 3032 bytes
  (MTU-bounded; larger inputs are not supported); GCM re-expands the AES-NI
  key schedule per call by design. Source:
  `src/crypto/symmetric/aead/chacha/aead.c:32`,
  `src/crypto/symmetric/aead/gcm/gcm.c:158`.
- **HKDF, SHA-2 plain digest and RSA lack BoringSSL vectors** — upstream moved
  them out of FileTest files; covered by RFC/FIPS vectors instead. Source:
  `docs/security/boringssl-vectors.md`.

## Platform / I/O

- **IPv6 dual-stack only sockets (fixed)** — UDP sockets fall back from
  AF_INET6 to AF_INET on EAFNOSUPPORT (L12-24); the previous failure is
  fixed, noted so IPv6-disabled hosts are understood to work.
- **Linux x86-64 only** — ISA-specific code lives in `src/common/arch/x8664/`;
  other ISAs are not provided (inferred from the layout; see
  `docs/syscalls.md`).
- **`recvmmsg` batch cap** — `WIRED_RECVMMSG_MAX` 64 on-stack. Source:
  `src/transport/io/socket/io/udp.c:323`.
- **SO_REUSEPORT multi-worker** — workers share one UDP port only if the bind
  path enables `SO_REUSEPORT`; verify before relying on it. Source:
  `srvworkers.h:13`.
- **Test-only helpers unused in the freestanding build** — `srvrun_test_set_*`
  and the `srvworkers` child hook need `__attribute__((unused))`. Not a
  runtime limitation; recorded because `ponytail:` markers mention it. Source:
  `srvrun.c:4387`, `:5782`, `:5819`, `srvworkers.c:42`.
- **`printf`-compat deviations** (`wired_snprintf` family) — `%p` NULL prints
  `0x0`; `%f` saturates the integer part at 2^64 and caps precision at 40;
  `wired_dprintf` truncates output past 511 bytes. Source: L14-1,
  `src/common/fmt/fmt.h`.
- **AF_XDP path IPv4 only** — fixed 20-byte header, no options. Source:
  `ledger:rfc791.md`.
- **Hub and sockets tuning** — see [Capacity limits](#capacity-limits).

## Capacity limits

Fixed-size tables and buffers (BSS-sized; raise the constant and rebuild).

| Constant | Value | Where | Effect when exceeded |
|---|---|---|---|
| `WIRED_MOQTRUN_MAX_SESSIONS` | 32 | `moqtrun.h:36` | no free slot; raw: INTERNAL_ERROR close |
| `WIRED_MOQTRUN_MAX_SUBS` | 31 | `moqtrun.h:40` | subscribers per track |
| `WIRED_MOQTRUN_MAX_FILTER_RANGES` | 4 | `moqtrun.h:204` | REQUEST_ERROR INVALID_FILTER |
| `WIRED_MOQTRUN_MAX_REQ_UPDATES` | 4 | `moqtrun.h:210` | TOO_MANY_REQUEST_UPDATES (d19+) |
| `WIRED_MOQTRUN_IMPL_MAX` | 64 | `moqtrun.h:215` | MOQT_IMPLEMENTATION truncated |
| `WIRED_MOQTRUN_HOLD_BUF` | 2048 | `moqtrun.h:225` | pre-SETUP bytes: request reset EXCESSIVE_LOAD, Object dropped |
| `WIRED_MOQTRUN_GOAWAY_URI_MAX` | 512 | `moqtrun.h:230` | `wired_moqt_goaway` returns -1 for a longer URI (spec allows 8192) |
| `WIRED_MOQTRUN_MAX_RELAYS` | 4 | `moqtrun.h:422` | stream not relayed, subscribers miss it |
| `WIRED_MOQTRUN_MAX_NAME` | 64 | `moqtrun.h:427` | Track Name truncated |
| `WIRED_MOQTRUN_MAX_NS` | 128 | `moqtrun.h:433` | namespace refused on PUBLISH |
| `WIRED_MOQTRUN_MAX_TRACKS_PER_PEER` | 3 | `moqtrun.h:437` | PUBLISH refused |
| `WIRED_MOQTRUN_MAX_REQS` / `_PER_SESSION` | 64 / 16 | `moqtrun.h:476,481` | request stream reset EXCESSIVE_LOAD |
| `WIRED_MOQTRUN_MAX_RDV` / `_RDV_PER_SESSION` | 16 / 4 | `moqtrun.h:604,608` | SUBSCRIBE refused EXCESSIVE_LOAD |
| `WIRED_MOQTRUN_RDV_MAX_MS` | 1500 | `moqtrun.h:615` | longer hold times out (deviation) |
| `WIRED_MOQTRUN_MAX_UP` | 16 | `moqtrun.h:659` | upstream waiter refused EXCESSIVE_LOAD |
| `WIRED_MOQTRUN_MAX_FETCHES` (+ fetch_waits) | 8 (+8) | `moqtrun.h:690` | REQUEST_ERROR INTERNAL_ERROR |
| `WIRED_MOQTRUN_GOAWAY_GRACE_MS` | 1000 | `moqtrun.h:699` | fixed grace |
| `WIRED_MOQTRUN_PUBDONE_WAIT_MS` | 2000 | `moqtrun.h:707` | remaining streams reset |
| `WIRED_MOQTREL_POOL` | 4 | `moqtrel.h:26` | further reliable tracks use the lossy path |
| `WIRED_MOQTREL_CAP` | 3 x `WT_BUF_CAP` | `moqtrel.h:31` | ring size |
| `WIRED_MOQTREL_STALL_MS` | 10000 | `moqtrel.h:38` | slow subscriber shed (reset) |
| `WIRED_MOQTREL_MAX_SUBS` / `_MARKS` | 31 / 8 | `moqtrel.h:53,56` | cursors / early-timeout marks |
| `MOQCACHE_OBJ_MAX` | 65472 | `moqcache.h:34` | larger Object not cached |
| `WIRED_WT_MAX_BUFFERED_DATAGRAMS` / `_CAP` | 4 / 256 | `session.h:49,55` | payload truncated |
| `SRVRUN_MAX_WT_SESSIONS` | 2 | `srvrun.c:181` | per-connection WT sessions |
| `WIRED_SRVRUN_RESP_MAX` | 16384 | `srvrun.c:912` | larger body needs bigbuf/streaming |
| `WIRED_SRVLOOP_BODY_MAX` | 1024 | `respond.c:272` | handler body cap |
| `SRVRUN_RX_BATCH` | 16 | `srvrun.c:1033` | recvmmsg batch |
| `WIRED_SRVLOOP_MAX_STREAMS` | 40 | `srvloop.h:108` | request slots |
| `WIRED_SRVLOOP_MAX_WT_STREAMS` / `_UNI_STREAMS` | 24 / 9 | `srvloop.h:223,369` | WT bidi / uni slots |
| `WIRED_SRVLOOP_WT_BUF_CAP` | 49152 | `srvloop.h:244` | per-slot receive window |
| `WIRED_SRVLOOP_MAX_RX_DATAGRAMS` / `_CAP` | 256 / 1200 | `srvloop.h:449,456` | datagram queue |
| `BODYWIN_CAP` | 2048 | `body_window.h:12` | request bytes truncated |
| `WIRED_SRVLOOP_CTRL_BUF_CAP` | 512 | `srvloop.h:193` | control bytes truncated |
| `WIRED_CONNTABLE_CAP` | 64 | `conntable.h:18` | no new connection |
| `ZERORTT_SEEN_CAP` | 4096 | `zerortt_seen.h:17` | oldest evicted |
| `TICKETGUARD_CAP` | 64 | `ticketguard.h:17` | oldest evicted |
| `WIRED_RECVMMSG_MAX` | 64 | `udp.c:325` | batch cap |
| `SRVRUN_RAW_CLOSE_REASON_MAX` | 48 | `srvrun.c:3830` | reason cut |

## Testing and verification gaps

- **Real-peer verification pending (`[~]`) items** — rendezvous, upstream
  SUBSCRIBE and raw-QUIC wire items stay `[~]` until confirmed against a real
  peer (moq-rs `rendezvous-timeout`, etc.). Source: L12-1, L12-3, L13-9,
  L13-11. Per project rule, wire-format features are not `[x]` on loopback
  alone.
- **Interop runs are in a fork** — the interop-runner changes (`wired-quic`
  registration, workflow integration) exist only on the fork's main
  (Hakkadaikon/moq-interop-runner) and are not proposed upstream, so public
  interop results do not include them. Source: RESUME, `tasks/moqt-multidraft-ledger.md:255`.
- **Peer coverage** — WebTransport relay `wired` 12/14, raw `wired-quic` 13/14;
  the misses are client/transport mismatches only, 0 wired-attributed
  failures. Source: RESUME.
- **Valgrind** — 7 reports on BPF attr structs are expected false positives
  (the kernel zero-fills past the given size); 5 reports in `srvworkers_test`
  are timing-dependent under valgrind. Source: RESUME, L13-12.
- **Flaky test** — `tests/app/srvthreads_datagram_test.c:1095`
  (`sdt_run_wt_stages` stage CHECKs) fails rarely. Source: RESUME.
- **Test builds differ** — `just test-fast` shard TUs can hide a static/typedef
  collision that only the single-TU `just test` sees (see
  `.claude/rules/build-and-verify.md`).
- **Fuzz coverage** — `fuzz_moqt` covers codecs, `moqdg`, `moqcache`; the hub
  run loop (`moqtrun`) is not fuzzed (not a codec). Source: L7-5.
- **Ledger counts** — 7 requirements are `[ ]` (untested): MQ18-118a,
  MQ22-070a, MQ22-083a, MQ22-108b, MQ22-137, MQ22-137a, 8446-053. Source:
  `docs/features/README.md`, individual ledgers.
- **Ledger drift** — the draft-19 ledger cites a renamed test
  (`test_moqtrun_subscribe_nonzero_timeout_rejected`, now `_accepted`) that
  `check_features.py` flags. Source: `tasks/moqt-multidraft-ledger.md:261`.
- **BoringSSL oracle** — no failures; skipped: 179 ECDSA P-224/P-521/secp224k1,
  15 HMAC MD5/SHA1/SHA224/SHA512, 7 AES-GCM non-96-bit nonces, the
  1,000,000-iteration X25519 case. Source: `docs/security/boringssl-vectors.md`.
- **Self-loopback is not interop** — features touching the wire stay `[~]`
  until pinned to an RFC vector or a real-peer trace.

## Out of scope by design

These are marked by the ledgers as operator, application, client or
intermediary concerns, not SDK code (the ledgers exclude them from the
coverage denominator).

- **Client roles** — client-side TLS/QUIC/HTTP/3/WebTransport behaviour
  (ClientHello construction, Version Negotiation reaction, 0-RTT client rules,
  redirect following, WT-Available-Protocols construction). Source: all
  `ledger:rfc9*.md`, `ledger:draft-webtrans-http3.md`.
- **Intermediary / proxy behaviour** — HTTP caching, Via/Forwarded, CONNECT
  to TCP, capsule re-expression, QPACK re-encoding, relay-to-relay
  coordination and Session Migration. Source: ledgers.
- **Operator guidance** — load balancer CID routing, Alt-Svc, DSCP/QoS, NAT
  timeouts, key lifecycle, cross-protocol and privacy considerations
  (RFC 9312, 9308, MoQT security sections). Source: ledgers.
- **MoQT URI / name rendering** — `moqt` URI scheme and dereferencing, SVCB;
  human-readable names (compared as raw bytes). Source: ledgers.
- **E2E object encryption (SFRAME / Secure Objects)** — external mechanism.
  Source: `ledger:draft-moq-transport-22.md`.
- **Revocation and PKI operations** — CRL, OCSP, CA issuance rules, pinning,
  reference-identifier construction (caller policy). Source: `ledger:rfc5280.md`,
  `ledger:rfc6125.md`.
- **Legacy TLS** — TLS <= 1.2, record layer, KeyUpdate message, EndOfEarlyData,
  middlebox compatibility mode (superseded by QUIC). Source: `ledger:rfc8446.md`.
- **Rate-limit headers, HTTP/2 WebTransport, HTTP/1.x/2 datagrams.** Source:
  `ledger:draft-webtrans-http3.md`, `ledger:rfc9297.md`.
- **Re-open conditions recorded in the MoQT ledger** — draft-14 to -17 (a
  peer that speaks only <= 17), raw-QUIC 0-RTT, per-transport GOAWAY URI, a
  wired-side raw MoQT client role. Source: L "対象外", L13.

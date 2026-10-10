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

Last reviewed: 2026-10-09

Source shorthand: `L<n>` = `tasks/moqt-multidraft-ledger.md` item `<n>` (e.g.
`L12-3` is item 12-3); `RESUME` = `tasks/moqt-multidraft-RESUME.md`;
`ledger:<file>` = a file in this directory; `file:line` = a `ponytail:` comment
or definition in the tree at the review date (line numbers drift, grep the
quoted name if a line has moved).

Contents: [MoQT relay (hub)](#moqt-relay-hub) |
[MoQT versions and spec deviations](#moqt-versions-and-spec-deviations) |
[MoQT track switching (experimental)](#moqt-track-switching-experimental) |
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
- **SUBGROUP before SUBSCRIBE_OK dropped** — a SUBGROUP stream that reaches the
  hub before the upstream SUBSCRIBE_OK is dropped, not buffered (unverified;
  from the hand-off brief, no code comment found). Impact: first Objects of a
  publisher that races its own SUBSCRIBE_OK. Source: L12-3 area.
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
- **OBJECT_DELIVERY_TIMEOUT start point is "leading byte of the Object"** —
  d19 ("first payload byte") and d22 ("last header byte") collapse to the same
  moment because Objects decode atomically. Source: `moqtrun.c:5676`, L4-11,
  `ledger:draft-moq-transport-22.md` MQ22-070a (`[ ]`).
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
  ledgers, Out of scope. (RENDEZVOUS_TIMEOUT is acted on since L12-1.)
- **Track Properties never forwarded in SUBSCRIBE_OK** — the tail is always
  empty, so INCLUDE_PROPERTIES (0x35, d22 9.20.21) = 1 is decoded but has no
  effect (= 0 is honored, MQ22-083a). Source: `moqtrun_queue_subscribe_ok`.
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
- **Range Filters do not exist in draft-18** — the hub closes a d18 session
  that sends one (unknown parameter type). Source: ledger:draft-moq-transport-18.md.

## MoQT track switching (experimental)

The moqtail-compatible SWITCH_FROM (0x24) / SSTS (0x41, Setup Option 0x09)
extension ([overview](moqt-track-switching.md)) is opt-in through
`wired_moqt_hub.switch_track` and `ssts_algs` / `ssts_alg_n`, and works on
draft-22 sessions only. None of it is part of draft-22. Source shorthand:
`PLAN` = `tasks/moqt-trackswitch-plan.md`.

- **Loopback-tested only** — the codec is pinned to moqtail-rs unit-test
  byte vectors, and the hub behaviour is tested in-process. No moqtail (or
  other third-party) peer has been run against it. Source:
  `ledger:draft-moq-transport-22.md` MQ22-X13.
- **Two or more active sets pin backpressure to the lowest tier** —
  algorithm 0xff01 sums stream depth over all of a session's active sets.
  With one open stream each, two sets already read as depth 2
  (`MOQSSTS_DOWNSHIFT_DEPTH`), so every set stays on its lowest member.
  This is inherited from moqtail. Impact: a moqt_chat viewer watching two
  or more sharers in Auto gets only the lo variants. Source:
  `src/app/moqt/ssts/moqssts.h` (`moqssts_bp_decide` doc),
  `test_moqssts_two_active_sets_are_pinned_to_the_lowest_tier`.
- **Backpressure observes once per Group of the pacing set** — moqtail also
  observes on a 100 ms tick. Here the session's tier machine moves only
  when its pacing set (the lowest-slot active backpressure set) decides a
  Group; other backpressure sets take the current tier, clamped to their
  own ladder, without observing. An upshift therefore needs 5 clear Groups
  of the pacing set (`MOQSSTS_UPSHIFT_GOP_STREAK`), about 5 GOPs (about
  10 s with moqt_chat's 2 s keyframes). Depth counts a stream from its open until the
  hub relays the publisher's FIN, not until the subscriber acknowledges it.
  The timeout input is the session's hub-side stream resets (busy shed,
  DELIVERY_TIMEOUT, reliable stall) on any of its streams, chat and audio
  included, as moqtail counts any stream of the connection. It is counted
  only while the session has a backpressure set, not moqtail's discard
  timer. Source:
  `src/app/moqt/run/moqtssts_run.c` header comment.
- **The default algorithm (0) has a static budget** — there is no
  bandwidth estimator. The budget is `wired_moqt_hub.ssts_cap_kbps`, and 0
  means unlimited, which always picks the highest member. Source:
  `moqtrun.h` (`ssts_cap_kbps`), `moqtssts_run.c`.
- **SWITCHING_SET_ASSIGNMENT in PUBLISH_OK / REQUEST_OK is unsupported** —
  moqtail accepts it there, but this hub accepts it in SUBSCRIBE and
  REQUEST_UPDATE (subscription) only. Elsewhere it is not an allowed
  parameter (a decode violation). Source: PLAN §0, `MOQCTL_PARAM_RULES` in
  `src/app/moqt/ctl/moqctl.c`.
- **A mid-Group joiner of a set waits for the next Group** — the decision
  for a Group is made at its first arrival and is final. A member that
  subscribes after that has no verdict for the current Group, so its first
  forwarded Group is the next one. Fills and FETCH are not gated by SSTS.
  Source: `moqtssts_run.h` (gate model), design SS-1.
- **No switch prompt, GOP extension or latency budget** — these come from
  the "Art of the Switch" talk but are not in moqtail's code either, so
  they are out of scope. Source: PLAN §0.
- **SWITCH_FROM and SSTS do not combine on one subscription** — a
  SWITCH_FROM naming a member of a switching set is refused INVALID_SWITCH
  (0x32). Use the set (sender-side) or explicit switches (receiver-side),
  not both. Source: `moqtswitch.c`.
- **SWITCH_FROM with FILL_PARAMETERS is refused** — INVALID_SWITCH (0x32).
  A switched-to subscription starts at the boundary G and gets no history
  fill. Source: `test_moqtrun_switch_fill_refused`.
- **Hard mode cuts when Group G reaches the hub, not the subscriber** — the
  old subscription ends once the new track's Largest Group is at least G
  (by stream or datagram). If the hub cannot open the new Group-G stream
  to the subscriber yet (no stream credit, or a backlog), the old in-flight
  Groups are RESET first, so there is an explicit gap. The new Group G then
  arrives through a late open and may lose its first Object. Source:
  `src/app/moqt/run/moqtswitch.c`, `tasks/loopeng/moqt/TrackSwitch/design.md`
  TS-4.
- **A suspended subscription holds its slots** — without Publish Done
  (flag 0x80), the switched-away subscription stays (FORWARD 0, request
  stream open) so that it can be switched back. It keeps its subscriber
  slot and request stream until the subscriber cancels it or the session
  closes. Source: `moqtswitch.h` (`moqtsw_suspend`).
- **Only request-stream subscriptions can join a switching set** — a
  SWITCHING_SET_ASSIGNMENT on a control-stream SUBSCRIBE (one that can
  silently re-attach when its publisher returns), or on a SUBSCRIBE to
  the hub's own tracks, is refused UNSUPPORTED_EXTENSION (0x33). Draft-22
  request-stream subscriptions end with PUBLISH_DONE when the publisher
  goes away, so their set membership never outlives the track. Source:
  `test_moqtrun_ssts_ctrl_subscribe_refused`.
- **A member lagging more than 5 Groups is decided again** — decisions
  are kept per set for its newest Group minus 5 (moqtail's window). A
  member that delivers a Group older than that gets a fresh decision, so
  such a late Group can come from both members. Source:
  `test_moqtrun_ssts_lag_outside_window`.
- **An idle pacing set freezes backpressure** — if the pacing set's
  publisher keeps its track but stops sending Groups (a paused share), no
  observation happens, so the session's other backpressure sets stay on
  the current tier. Resets counted in the meantime are consumed at once
  at the pacer's next Group, which can cause one extra downshift. Source:
  `src/app/moqt/run/moqtssts_run.c` header comment.
- **A cross-publisher switch can lose its boundary across a reconnect** —
  if the old track's publisher reconnects while the switched-to track's
  publisher (a different session) stays live, the new subscription is
  released from its boundary before the old one re-attaches. A later
  LOCATION_FILTER update on the new subscription is then no longer
  clamped to G, so a few Groups could reach the subscriber from both
  tracks. This needs a cross-publisher switch, a reconnect and a filter
  update together. Source: `moqtsw_old_alive` in
  `src/app/moqt/run/moqtswitch.c`.
- **Busy-shed can downshift without network congestion** — the lossy
  relay resets a subscriber stream after `WIRED_MOQTRUN_RESET_AFTER_BUSY`
  (8) refused rounds, a threshold tuned for 20 ms voice, and every such
  reset feeds backpressure. A 1080p screen share at about 3 Mbps on
  loopback hit it in 2 of 3 browser runs, so Auto went to lo with no cap
  in place. A shed Group of a switching-set member is not re-opened
  mid-way; a track outside any set (voice) still is. Source: `moqtrun_relay_shed_one` in `src/app/moqt/run/moqtrun.c`, W6
  browser run (PLAN §4).
- **Variants must share Group numbers** — the boundary rule assumes aligned
  Group IDs across the variant tracks. The hub does not check this.
- **Soft give-up is fixed** — `WIRED_MOQTSW_SOFT_WAIT_MS` (4000 ms, two
  moqt_chat keyframe Groups) of wall-clock time after the switch. The hub
  gives up only while nothing of the old subscription below G is still
  live. Groups of the old subscription that arrive later are
  dropped. Source: `moqtswitch.h:52`.

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
- **Close reasons bounded by one minimum-size packet** — the hub's
  application CONNECTION_CLOSE (0x1d) reason phrase is cut (at a UTF-8
  boundary) to `SRVRUN_RAW_CLOSE_REASON_MAX` = 1148, what fits next to the
  frame overhead in a 1200-byte datagram; every kept WT close message
  (<= 1024 bytes) goes out whole. Source: `srvrun.c` (`SRVRUN_CLOSE_PL_MAX`).
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

- **Control stream backlog capped** — the peer control stream's unparsed
  backlog must fit `WIRED_SRVLOOP_CTRL_BUF_CAP` (512); a larger frame or gap
  closes with H3_EXCESSIVE_LOAD. Source: `srvloop/priority_ctrl.c`.
- **Out-of-order gap ranges** — a WT stream tracks at most
  `WIRED_SRVLOOP_WT_MAX_RANGES` (8) disjoint gaps in one window; more are
  coalesced or dropped (not reachable at targeted sizes). Source:
  `srvloop.c:647`.
- **Pending broadcast datagrams per connection** — `SRVRUN_DG_PENDING_Q` (4)
  of up to 1200 bytes; a full queue refuses the newest. Source: `srvrun.c`.
- **Pre-establishment datagram buffering is bounded** —
  `WIRED_WT_MAX_BUFFERED_DATAGRAMS` (4) datagrams of up to
  `WIRED_WT_BUFFERED_DATAGRAM_CAP` (256) bytes; longer ones are dropped whole
  (never truncated). Source: `src/app/webtransport/session/session/session.h:52`.
- **Datagram drain is a fixed slice, not congestion-controlled** —
  `SRVRUN_DGRING_DRAIN_MAX` 16 / `_MS` 5 / `_BYTES` 3000 (about 4.8 Mbps).
  Source: `srvrun.c:5670`.
- **MAX_DATA ignores control/QPACK bytes** — the connection ceiling counts WT
  streams, streamed request bodies and CONNECT-stream capsules; control and
  QPACK stream bytes ride on the initial 10 MB (`STP_DEFAULT_MAX_DATA`).
  Source: `srvrun.c` (`srvrun_grant_conn_credit`).
- **Concurrent WT sessions per connection** — `SRVRUN_MAX_WT_SESSIONS` (2)
  with a global cap `WIRED_CONNTABLE_CAP` and `SRVRUN_MAX_WT_SESSIONS_PER_WINDOW`
  (10). Source: `srvrun.c:181`, `srvrun.c:198`, `srvrun.c:218`.
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
- **Request buffer limited to `BODYWIN_CAP` (2048)** — a buffered request
  that fills the window without FIN is answered 413/431, including one whose
  FIN comes in a later empty frame ("window stuck"); a byte past the window is
  past the stream credit and closes with FLOW_CONTROL_ERROR. Source:
  `srvloop/dispatch.c` (`route_window_stuck`).
- **Abort retransmit table is fixed-size** — `SRVRUN_RST_RETX` keeps one
  abort per trackable stream (92); more than that unACKed within one RTT
  would send the excess once without retransmission (RFC 9000 13.3).
  Source: `srvrun.c` (`srvrun_rst_keep`).
- **STOP_SENDING before the response starts is not remembered** — a peer
  STOP_SENDING is answered with RESET_STREAM (RFC 9000 3.5) only on a send
  part that already exists (response slot, WT send slot, CONNECT stream); one
  arriving while the request is still being read leaves the later response
  to run normally. Source: `srvrun.c` (`srvrun_answer_peer_stops`).
- **Graceful shutdown is tick-bounded** — GOAWAY then at most
  `SRVRUN_DRAIN_TICKS` (25) x 200 ms (about 5 s) before close; a SIGTERM before
  the handler is installed takes the default action (no GOAWAY). Source:
  `srvrun.c:10245`, `srvrun.h:277`.
- **Spin backoff is count-based** — no time-based backoff (the only clock is
  millisecond-granular). Source: `srvpoll/srvpoll.c:11`.
- **Receive batch** — `SRVRUN_RX_BATCH` (16) datagrams per recvmmsg, 32 KB per
  env. Source: `srvrun.c:1033`.
- **Idle timeout and eviction grace fixed** — `WIRED_SRVRUN_IDLE_MS` 30000,
  `WIRED_SRVRUN_EVICT_GRACE_MS` 1000. Source: `srvrun.c:5995`, `srvrun.c:9908`.

## QUIC transport

- **Retry token and ticket keys derive from compiled-in seeds** — both keys
  rotate every `KEYRING_PERIOD_SECS` (2 h) and the previous key still opens,
  but the seeds (`g_srvrun_retry_key`, respond.c `g_ticket_key`) are
  constants in the source, so anyone holding the source can derive them.
  Impact: a deployment that needs unforgeable tokens/tickets must replace
  the seeds. Source: `src/tls/keys/keyring/keyring.h`.
- **Preferred-address migration is one-way sticky** — once on the
  preferred-address socket, old-path stragglers cannot flip a connection back;
  there is no general per-path highest-packet-number tracking. Source:
  `srvrun.c:9425`.
- **ECN-failed connections lose GSO** — a connection whose ECN validation
  failed sends Not-ECT through a per-datagram TOS cmsg, one `sendmsg` per
  packet (no GSO batching); AF_XDP never marks. ECT(1) is never sent.
  Source: `srvrun.c` (`srvrun_ecn_unmarked`).
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

- **One ticket per connection** — every NewSessionTicket carries the
  one-byte `ticket_nonce` 0x00, unique only because the server issues a
  single ticket per connection; issuing more needs a per-connection counter.
  Source: `src/app/http3/server/srvloop/respond.c` (`build_ticket_message`).
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
- **Signature algorithms in chains** — chains signed with P-521 or legacy
  RSA-SHA-1 cannot be verified. Source:
  `tests/vectors/boringssl/README.md`.

## Cryptography

- **Hash / MAC set** — SHA-256, SHA-384 and SHA-512 shipped; **not** SHA-1,
  SHA-224, SHA-512/224, SHA-512/256, MD5. HMAC-SHA256, HMAC-SHA384 and
  HMAC-SHA512 only: **no HMAC-SHA1, HMAC-SHA224, HMAC-MD5**; HKDF is SHA-256
  only in the TLS/QUIC profile. Impact: none for TLS 1.3 handshakes; certificate chains signed with
  SHA-1 algorithms cannot be verified. Source:
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

- **Linux x86-64 only** — ISA-specific code lives in `src/common/arch/x8664/`;
  other ISAs are not provided (inferred from the layout; see
  `docs/syscalls.md`).
- **`recvmmsg` batch cap** — `WIRED_RECVMMSG_MAX` 64 on-stack. Source:
  `src/transport/io/socket/io/udp.c:323`.
- **SO_REUSEPORT multi-worker** — workers share one UDP port only if the bind
  path enables `SO_REUSEPORT`; verify before relying on it. Source:
  `srvworkers.h:13`.
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
| `WIRED_MOQTRUN_GOAWAY_URI_MAX` | 8192 | `moqtrun.h:230` | `wired_moqt_goaway` returns -1 for a longer URI (the spec maximum) |
| `WIRED_MOQTRUN_MAX_RELAYS` | 4 | `moqtrun.h:422` | stream not relayed, subscribers miss it |
| `WIRED_MOQTRUN_MAX_NAME` | 64 | `moqtrun.h:427` | Track Name refused (PUBLISH, hub-owned publish returns 0) |
| `WIRED_MOQTRUN_MAX_NS` | 128 | `moqtrun.h:433` | namespace refused on PUBLISH |
| `WIRED_MOQTRUN_MAX_TRACKS_PER_PEER` | 4 (3 before track switching) | `moqtrun.h:469` | PUBLISH refused |
| `WIRED_MOQTRUN_MAX_REQS` / `_PER_SESSION` | 96 / 24 | `moqtrun.h:509,514` | request stream reset EXCESSIVE_LOAD |
| `WIRED_MOQTRUN_MAX_RDV` / `_RDV_PER_SESSION` | 16 / 4 | `moqtrun.h:604,608` | SUBSCRIBE refused EXCESSIVE_LOAD |
| `WIRED_MOQTRUN_RDV_MAX_MS` | 1500 | `moqtrun.h:615` | longer hold times out (deviation) |
| `WIRED_MOQTRUN_MAX_UP` | 16 | `moqtrun.h:659` | upstream waiter refused EXCESSIVE_LOAD |
| `WIRED_MOQTRUN_MAX_FETCHES` (+ fetch_waits) | 8 (+8) | `moqtrun.h:690` | REQUEST_ERROR INTERNAL_ERROR |
| `WIRED_MOQTRUN_GOAWAY_GRACE_MS` | 1000 | `moqtrun.h:699` | fixed grace |
| `WIRED_MOQTRUN_PUBDONE_WAIT_MS` | 2000 | `moqtrun.h:707` | remaining streams reset |
| `WIRED_MOQTRUN_SSTS_SETS` | 8 | `moqtss.h:17` | SWITCHING_SET_ASSIGNMENT refused INTERNAL_ERROR |
| `MOQSSTS_MAX_MEMBERS` | 4 | `moqssts.h:24` | members per switching set |
| `MOQCTL_SSTS_MAX_ALGS` | 4 | `moqctl.h:121` | SSTS_ALGORITHMS ids kept/sent |
| `WIRED_MOQTSW_SOFT_WAIT_MS` | 4000 | `moqtswitch.h:52` | Soft switch gives up on the old track |
| `WIRED_MOQTREL_POOL` | 4 | `moqtrel.h:26` | further reliable tracks use the lossy path |
| `WIRED_MOQTREL_CAP` | 3 x `WT_BUF_CAP` | `moqtrel.h:31` | ring size |
| `WIRED_MOQTREL_STALL_MS` | 10000 | `moqtrel.h:38` | slow subscriber shed (reset) |
| `WIRED_MOQTREL_MAX_SUBS` / `_MARKS` | 31 / 8 | `moqtrel.h:53,56` | cursors / early-timeout marks |
| `MOQCACHE_OBJ_MAX` | 65472 | `moqcache.h:34` | larger Object not cached |
| `WIRED_WT_MAX_BUFFERED_DATAGRAMS` / `_CAP` | 4 / 256 | `session.h:49,55` | longer datagram dropped |
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
| `SRVRUN_RAW_CLOSE_REASON_MAX` | 1148 | `srvrun.c` | reason cut (unreachable: messages <= 1024) |

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
- **BoringSSL oracle** — no failures; skipped: 179 ECDSA P-224/P-521/secp224k1,
  12 HMAC MD5/SHA1/SHA224, 7 AES-GCM non-96-bit nonces, the
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

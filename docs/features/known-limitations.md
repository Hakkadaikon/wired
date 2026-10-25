# Known Limitations

This page lists every known limitation and every deliberate spec deviation of
the wired SDK, grouped by layer. Read it before you deploy wired, or when a
peer behaves in a way the spec allows but wired does not support. Each entry
starts with who is affected, then says what is limited and where in the code
(or in which per-spec ledger) it is recorded.

Last reviewed: 2026-10-15

## How to read this page

wired is a C library with no libc dependency that implements QUIC, HTTP/3,
WebTransport and MoQT (Media over QUIC Transport) on Linux. Many of its
limits exist on purpose. Every table is a fixed array sized at build time,
so a peer that needs more than a table holds is refused instead of being
served from new memory. The guide page
[Current limits](https://hakkadaikon.github.io/wired/guide/en/concepts/limits/)
lists the capacities an application meets first and the MoQT parts that are
not implemented. This page adds what the guide does not cover: the effect of
each overflow, the less visible limits, and the reason for each deviation.
Where the two pages disagree, the values on this page are taken from the
current code (checked on 2026-10-15) and win.

The entries come from three places:

- `ponytail:` comments in `src/`. This is the repo's marker for a limitation
  that was accepted on purpose, with a note on how to lift it.
- The "Not implemented" and "Out of scope" sections and the untested items of
  the per-spec ledgers in this directory (one Markdown file per RFC or
  draft).
- The skip tables of the BoringSSL test vectors.

A "Source:" line names the code symbol (function or macro) or the ledger
file. Section numbers such as "9.5" refer to the spec
the entry names.

MoQT terms (Track, Group, Subgroup, Object) follow the guide's
[media mapping](https://hakkadaikon.github.io/wired/guide/en/concepts/media-mapping/).
The **hub** is wired's built-in MoQT relay: publishers send it Objects and
it forwards them to subscribers
([guide](https://hakkadaikon.github.io/wired/guide/en/moqt/hub/)). "d18",
"d19" and "d22" mean draft-ietf-moq-transport-18, -19 and -22.

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

The hub is a single-process relay sized for one room of participants. It is
not a relay network: it has no upstream relay and no sibling relays. Three
terms recur below:

- An **upstream SUBSCRIBE** is the SUBSCRIBE the hub itself sends to a
  publisher to get a Track that its subscribers asked for (d18/d19 9.4, d22
  7.4).
- A **rendezvous** is a SUBSCRIBE the hub holds open until a publisher of
  that Track appears, instead of refusing it at once.
- A **reliable ring** is the per-track buffer the hub keeps so it can replay
  a stream to a subscriber that joins late. Each subscriber has a **cursor**
  (its read position in the ring), and the ring keeps **arrival marks**
  (timestamps it uses to apply a delivery timeout).

The limits:

- **One publisher per Track, one upstream at a time** — Affects: deployments
  where several publishers announce the same Track, or where a Track should
  fail over to another publisher. The hub keys one Track per Full Track
  Name, so a second publisher of the same name is not tracked separately,
  although d22 9.5 says "each publisher". Several publishers may share a
  namespace, but each Track has one; there is no aggregation or
  deduplication across publishers (d19 9.3, d22 7.4). The hub also never
  subscribes to several publishers of one Track at once. d22 7.6 says a
  relay MUST SUBSCRIBE to every matching publisher, and to each newly
  announcing one for every matching subscription. Here a later announce is
  used only while subscriptions wait for a new path (failover, below), and
  is ignored while an upstream subscription is active. Source:
  `moqtrun_up_key`, `moqtrun_track_ended` (ponytail); the MoQT ledgers' Out
  of scope sections.
- **Failover waits at most 1.5 s** — Affects: subscribers of a Track whose
  publisher drops while another publisher of the namespace is announced.
  The steps are:

  1. The upstream SUBSCRIBE ends on the publisher's side: PUBLISH_DONE with
     GOING_AWAY or INTERNAL_ERROR, a reset of the hub's stream, or the
     publisher's session closing.
  1. The downstream subscriptions wait up to `WIRED_MOQTRUN_RDV_MAX_MS`
     (1.5 s).
  1. Meanwhile the hub SUBSCRIBEs the other announcers of the namespace, one
     at a time.
  1. The first SUBSCRIBE_OK re-attaches the waiting subscriptions silently,
     under the Track Alias (the short number a subscriber uses for the
     Track) they already hold. If none answers by the deadline, each gets
     PUBLISH_DONE with the status of the end.

  Any other PUBLISH_DONE status, and a Malformed Track (a publisher that
  broke the Track rules, see below), ends the subscriptions at once.
  Source: `moqtrun_track_ended`.
- **Waits for a new path share the rendezvous table** — Affects: Tracks with
  many subscribers when their publisher drops. Each waiting subscription
  takes one slot of the hub-wide `WIRED_MOQTRUN_MAX_RDV` (16) table, at most
  `WIRED_MOQTRUN_RDV_PER_SESSION` (4) per session, with its own copy of the
  Track's deadline. When a Track has more waiting subscribers than free
  slots, it fails over only partly: the rest get PUBLISH_DONE with the
  status of the end at once. While the table is full, every new rendezvous
  hold is refused with EXCESSIVE_LOAD, for up to 1.5 s. How a wait
  interacts with track switching is listed under
  [MoQT track switching](#moqt-track-switching-experimental). Source:
  `moqtrun_rp_wait`.
- **One SUBGROUP stream kept before SUBSCRIBE_OK** — Affects: publishers
  that start sending before they answer the hub's SUBSCRIBE. A SUBGROUP
  stream that reaches the hub before the upstream SUBSCRIBE_OK is kept (one
  per publisher session, up to `WIRED_MOQTRUN_EARLY_BUF` = 2048 bytes) and
  relayed when the OK arrives. A second such stream, or one that outgrows
  the buffer, is dropped. Source: `moqtrun_early_stash`.
- **Late replay from a reliable ring is bounded** — Affects: subscribers
  that join in the middle of a stream. A subscriber that arrives while the
  ring holds a stream gets that stream replayed, starting from the stream's
  first Object at or past the subscriber's start Object. This works only
  while the ring has not wrapped or been reclaimed past the stream's header,
  and only once an Object at or past the start Object has arrived.
  Otherwise that stream is not sent to the subscriber. Source:
  `moqtrun_rel_replay_ok`, `moqtrun_rel_replay` (ponytail).
- **Late joiners skip a stream whose first delivery was torn** — Affects:
  subscribers joining a stream whose header uses Subgroup ID mode 0b01 (the
  Subgroup ID is the ID of the stream's first Object). "Torn" means an
  Object was split across two deliveries. When the first delivery of such a
  stream ends inside its first Object, the hub saves no stream header, so
  later joiners of that stream are skipped. Source:
  `moqtrun_relay_save_hdr` (ponytail).
- **Subscriber-less ring holds its publisher** — Affects: publishers of a
  reliable track nobody has subscribed to yet. A ring that no cursor has
  joined may hold the publisher up to `WIRED_MOQTREL_STALL_MS` (10000 ms).
  Source: `moqtrun_rel_drain_one` (ponytail).
- **Ring arrival marks absorb appends** — Affects: tracks that use a
  delivery timeout. With all `WIRED_MOQTREL_MARKS` (8) taken, the newest mark
  absorbs further appends, so a delivery timeout can fire early by at most
  the time since that mark. Source: `moqtrel_mark` (ponytail).
- **Fill and FETCH capacity refusal** — Affects: rooms where many
  subscribers ask for history at once. A fill is the history a SUBSCRIBE
  asks for; a FETCH asks for a range of past Objects
  ([guide](https://hakkadaikon.github.io/wired/guide/en/moqt/fetch/)). Fills
  beyond `fetches[]` + `fetch_waits[]` (8 + 8, both sized by
  `WIRED_MOQTRUN_MAX_FETCHES`) are refused with REQUEST_ERROR
  INTERNAL_ERROR before the OK is sent. They are never dropped silently.
  Source: `moqtrun_fill_room`, `moqtrun_fill_wait_put` (ponytail).
- **A FETCH's own Subscriber Priority is not kept** — Affects: clients that
  rank several FETCHes against each other. A fill uses its subscription's
  Subscriber Priority; a Standalone FETCH uses the default. Source:
  `moqtrun_fetch_sub_prio` (ponytail).
- **Upstream FETCH is one request per FETCH, passed through** — Affects:
  FETCHes of ranges the hub's cache does not fully hold. If the cache lacks
  the start of a FETCH range, the hub asks upstream once (the Track's
  publisher, else an announcer whose namespace covers it) and passes the
  Objects through as they arrive. It does not merge, retry or cache them.
  This upstream request is called a "leg" below. An application can observe
  these effects. Two FETCHes of one range are not merged into one upstream
  FETCH. A GOAWAY on the upstream request stream ends the leg instead of
  re-issuing it. Relayed Objects are not cached. The leg's time budget is
  fixed at `WIRED_MOQTRUN_UPFETCH_BUDGET_MS` (2000 ms) unless FILL_TIMEOUT is
  shorter. A leg that ends in the middle of an Object resets the downstream
  fetch stream with INTERNAL_ERROR, because the cache side cannot resume
  mid-Object. This happens when the upstream cuts the Object, when the budget
  runs out while part of it still waits to be written, or when the held tail
  does not fit. A d19 Joining FETCH (one that starts relative to a live
  subscription) is still served from the cache only. A Descending FETCH
  (newest Group first) of a Track the hub does not hold is reset when its
  upstream FETCH fails, because the hub knows nothing of that range to mark.
  The cache side applies no Range Filter, so MQ22-137 stays open.

  Buffering details: an Object under `WIRED_MOQTRUN_RELAY_FRAG_MAX` (16 KiB)
  is held whole while it is torn; a larger one's payload passes through as
  it arrives, and a write the transport refuses is retried on the next tick
  or delivery. One hub-wide buffer keeps what a leg holds, so a second leg
  that needs it at the same time gives up its upstream FETCH. If a
  FETCH_HEADER arrives split across deliveries while the peer's single early
  slot is already taken, every upstream FETCH to that peer that is still
  waiting for its data stream ends. Source: `moqtrun_upf_*`; requirements
  MQ22-213 to MQ22-219 and MQ22-137 in
  [draft-moq-transport-22.md](draft-moq-transport-22.md).
- **Object cache is arena-scanned** — Affects: hubs with a large FETCH
  cache. The cache lives in an arena (one memory block) the application
  passes in. Eviction compacts the arena with one memmove pass, and lookups
  scan it linearly. A one-entry resume point lets a forward walk over one
  track continue where its last lookup stopped. So a FETCH or FETCH_OK walk
  costs O(arena) per walk plus O(arena) per gap it crosses (the gap check
  rescans), not per Object. FETCHes of different tracks served in turn share
  that one entry and rescan from the start. Groups are assumed to arrive in
  ascending order per track, so an Object of an older Group is cached as if
  new. The largest cached payload is `MOQCACHE_OBJ_MAX` (65472 bytes).
  Source: `moqcache.h` header comment, `moqtrun_fetch_last`.
- **Discovery syncs are quadratic** — Affects: hubs with many namespace
  subscriptions
  ([guide](https://hakkadaikon.github.io/wired/guide/en/moqt/discovery/)).
  SUBSCRIBE_NAMESPACE catch-up is an O(reqs^2) scan per event, and
  SUBSCRIBE_TRACKS sync is O(sessions x tracks x reqs). This is fine at the
  fixed capacities. Source: `moqtrun_disc_sync`,
  `moqtrun_subtracks_sync_track`.
- **Range Filters are stream- or track-granular** — Affects: subscribers
  that filter below the stream level. A Range Filter is a SUBSCRIBE
  parameter (d19 and d22) that limits which streams or Objects are
  delivered. SUBGROUP_FILTER and PRIORITY_FILTER gate a whole stream when it
  opens toward the subscriber, using its header's Subgroup ID and Publisher
  Priority. TRACK_PROPERTY_FILTER selects the tracks a SUBSCRIBE_TRACKS is
  offered, by Track Properties up to 32 bytes (see "Track Properties"
  below). OBJECTID_FILTER gates datagrams only, and OBJECT_PROPERTY_FILTER
  is not evaluated: the hub does not cut single Objects out of a relayed
  stream. If a SUBSCRIBE_TRACKS carries several filter sets, and one set's
  TRACK_PROPERTY_FILTER fails while another set admits the track, the
  object filters of the failing set still admit Objects. Source:
  `moqtrun_sub_rngf_stream`, `moqtrun_subtracks_tp_pass`.
- **No Alias token cache** — Affects: clients that send auth tokens by alias
  ([guide](https://hakkadaikon.github.io/wired/guide/en/moqt/authorize/)).
  An auth token can be sent by alias: REGISTER stores one, USE_ALIAS refers
  to it, and DELETE drops it. The hub does not advertise
  MAX_AUTH_TOKEN_CACHE_SIZE, so its cache is 0 bytes. A REGISTER closes the
  session with AUTH_TOKEN_CACHE_OVERFLOW, and DELETE or USE_ALIAS closes it
  with UNKNOWN_AUTH_TOKEN_ALIAS (d22 8.9). FETCH and SETUP tokens are not
  inspected. Source: `moqtrun_take_tok_or_close`.
- **OBJECT_DELIVERY_TIMEOUT starts at the leading byte of the Object** —
  Affects: peers that measure the timeout from a different byte. d19 starts
  the clock at the first payload byte and d22 at the last header byte. Both
  fall on the same moment here because Objects decode atomically. Source:
  `moqtrun_relay_born` (ponytail),
  [draft-moq-transport-22.md](draft-moq-transport-22.md) MQ22-070a
  (untested).
- **Priority scheduling** — Affects: subscribers that change priority in the
  middle of a subscription
  ([guide](https://hakkadaikon.github.io/wired/guide/en/moqt/priority-goaway/)).
  The send pump orders Object streams by Subscriber Priority, then
  Publisher Priority, then group order, and puts fill before live inside
  one subscription. One-shot streams already queued are not re-prioritized
  by a REQUEST_UPDATE. Datagrams bypass the stream classes and are sent at
  once. Equal priorities across subscriptions share each pump pass
  round-robin. Source: `moqtrun_upd_resched` (ponytail); the Out of scope
  sections (section 7 / section 5) of the MoQT ledgers
  ([d19](draft-moq-transport.md), [d18](draft-moq-transport-18.md),
  [d22](draft-moq-transport-22.md)).
- **Properties are opaque** — Affects: applications that expect the relay to
  act on Properties. MAX_CACHE_DURATION, DEFAULT_PUBLISHER_GROUP_ORDER,
  DYNAMIC_GROUPS, Immutable Properties and Prior Group/Object ID Gap (and
  d22's TIMESTAMP, VIDEO_FRAME_MARKING, AUDIO_CONFIG, ENCRYPTED_LIST and
  PADDING) are relayed unchanged and never interpreted. Source: the MoQT
  ledgers' Out of scope sections.
- **FILL_TIMEOUT, EXPIRES and NEW_GROUP_REQUEST are decoded, not acted on**
  — Affects: clients that rely on these parameters. FILL_TIMEOUT's presence
  only decides whether a missing range is marked "End of Timed-Out Range"
  (d22: the hub could not get it in time), and it can shorten the upstream
  FETCH budget above. EXPIRES and NEW_GROUP_REQUEST are parsed and ignored.
  RENDEZVOUS_TIMEOUT, in contrast, is acted on (see the rendezvous cap in
  [MoQT versions and spec deviations](#moqt-versions-and-spec-deviations)).
  Source: the MoQT ledgers' Out of scope sections.
- **Track Properties forwarded in SUBSCRIBE_OK only, up to 32 bytes** —
  Affects: subscribers that read Track Properties. The publisher's Track
  Properties reach a subscriber's SUBSCRIBE_OK unless it sent
  INCLUDE_PROPERTIES (0x35, d22 9.20.21) = 0. A block longer than
  `WIRED_MOQTRUN_TRACK_PROPS_MAX` (32) is forwarded empty. TRACK_STATUS_OK,
  FETCH_OK and the PUBLISH of a SUBSCRIBE_TRACKS carry none. Source:
  `moqtrun_queue_subscribe_ok`.
- **Padding Datagrams are not sent** — Affects: deployments that need
  traffic padding. Source: the MoQT ledgers (section 11.5).
- **No Session Migration or REDIRECT behavior** — Affects: clients that
  expect to be moved to another relay. The hub never sends REDIRECT and does
  not react to one, because it has no upstream relay or sibling to move a
  requester to. Source: the MoQT ledgers' Out of scope sections.
- **REQUEST_UPDATE of a SUBSCRIBE_TRACKS** — Affects: clients that update a
  SUBSCRIBE_TRACKS. TRACK_NAMESPACE_PREFIX and FORWARD apply to the PUBLISHes
  generated afterwards. A TRACK_PROPERTY_FILTER in the update is accepted but
  not applied; the request keeps its own. Source: `moqtrun_upd_ns_forward`,
  `moqtrun_upd_ns_prefix`.
- **Malformed-Track detection is partial** — Affects: subscribers of a
  publisher that breaks the Track rules. Besides an unknown Object Status
  and an Object ID overflow at decode, the relay detects only an Object past
  the END_OF_TRACK Object or past its Group's latest END_OF_GROUP Object (by
  Status, not by the FIN of an END_OF_GROUP stream). It does not check a
  priority mismatch, differing finals, duplicate Objects with a different
  payload (that would need a cache lookup per Object), or a Delivery Mode
  change. The round that triggers the detection can still reach subscribers
  before their PUBLISH_DONE. Source: `moqtrun_track_obj` (d22 12.1).
- **Request IDs past 2^56 alias another** — Affects: a session that sends
  more than 2^56 requests (not reachable in practice). The hub keys each
  request's flow by session slot and the low 56 bits of its Request ID.
  Source: `moqtrun_flow_of` (ponytail).
- **Drained session grace is fixed** — Affects: slow peers during a
  GOAWAY. `WIRED_MOQTRUN_GOAWAY_GRACE_MS` (1000 ms) separates the
  PUBLISH_DONE flush from the GOAWAY_TIMEOUT close. It is a fixed wait, not
  a wait for acknowledgements. Source: `WIRED_MOQTRUN_GOAWAY_GRACE_MS`
  (ponytail).

## MoQT versions and spec deviations

- **Supported drafts: 18, 19 and 22 only** — Affects: peers that speak only
  another draft. Drafts 14 to 17 and drafts 20/21 are out of scope (their
  control-stream shape and varint use differ), and ALPN `moq-00` is not
  supported. Source: `moqver_caps`.
- **Deliberate deviation: Filter Type 250 accepted as Largest Object** —
  Affects: a strict peer that sends 250 and expects rejection. moxygen sends
  its own Filter Type 250 (LargestGroup), which is not in the spec. Closing
  with PROTOCOL_VIOLATION broke interop with moxygen, so the hub treats 250
  as Largest Object (`moqctl_locfilter_is_quirk`). Remove that branch for
  strict compliance. Source: commit `b217989`, `moqctl_locfilter_is_quirk`.
- **Deliberate deviation: rendezvous hold capped at 1.5 s** — Affects:
  publishers that legitimately arrive more than 1.5 s after a subscriber.
  The cap exists because imquic sends 500000 (microseconds) where
  milliseconds are expected and gives up after 2 s, so a longer hold broke
  interop with it. `WIRED_MOQTRUN_RDV_MAX_MS` is therefore 1500, and a
  rendezvous wait longer than 1.5 s ends with REQUEST_ERROR TIMEOUT. The
  draft lets a relay use a shorter timeout (10.2.6). Source: commit
  `03e69af`, `WIRED_MOQTRUN_RDV_MAX_MS`.
- **Range Filters do not exist in draft-18** — Affects: d18 clients that send
  one anyway. The hub closes a d18 session that sends one (unknown parameter
  type). Source: [draft-moq-transport-18.md](draft-moq-transport-18.md).
- **Descending FETCH may mark a nonexistent group tail as unknown** —
  Affects: clients that read End of Unknown Range markers in a descending
  FETCH. This follows d22 3.2.2 read literally, so it is not a deviation.
  The hub leaves groups and Objects that do not exist unmarked, and marks
  each group it cannot vouch for with its own End of Unknown Range marker
  that runs to the end of that group. So the marker also labels the tail of
  the previous item's group as unknown, even though that tail does not
  exist. Source: `moqtrun_fetch_descend`.

## MoQT track switching (experimental)

Track switching lets a subscriber move between variants of one stream (for
example a high and a low video quality). The moqtail-compatible SWITCH_FROM
(0x24) and SSTS (sender-side track switching: 0x41, Setup Option 0x09)
extension is opt-in through `wired_moqt_hub.switch_track` and `ssts_algs` /
`ssts_alg_n`, and works on draft-22 sessions only. None of it is part of
draft-22. The [overview](moqt-track-switching.md) defines the terms used
below; in short:

- SWITCH_FROM is a switch the subscriber asks for, from an old track A to a
  new track B at a boundary Group G. In **Hard** mode, A ends as soon as B's
  Group G reaches the hub. In **Soft** mode, A is allowed to finish its last
  Group first.
- With SSTS the hub switches for a **switching set** of variant tracks,
  Group by Group, based on what it measures about the subscriber's
  connection. A **tier** is a quality level, and the **pacing set** is the
  one set whose Groups drive tier changes.

The limits:

- **Loopback-tested only** — Affects: anyone who wants to use it with
  moqtail or another third-party peer. The codec is pinned to moqtail-rs
  unit-test byte vectors, and the hub behavior is tested in-process. No
  moqtail (or other third-party) peer has been run against it. Source:
  [draft-moq-transport-22.md](draft-moq-transport-22.md) MQ22-X13.
- **Backpressure is sampled once per pacing-set Group and once per 100 ms
  tick** — Affects: apps that call `wired_moqt_tick` rarely. The tier can
  move at each Group of the session's pacing set (its lowest-slot active
  backpressure set) and on `wired_moqt_tick` every 100 ms, as moqtail does.
  The tick runs only as often as the server loop calls `wired_moqt_tick`.
  Source: `moqtssts_run.c` header comment.
- **What backpressure counts as congestion** — Affects: sessions that mix
  switching-set tracks with chat or audio. Depth (the number of open streams
  toward the subscriber) counts a stream from its open until the hub relays the
  publisher's FIN, not until the subscriber acknowledges it. The other input is
  the hub's own resets of the session's streams, on any of its streams, chat
  and audio included, because moqtail counts any stream of the connection. A
  reset here is a busy shed (the lossy relay resets a stream the transport kept
  refusing, see below), a DELIVERY_TIMEOUT, or a reliable stall (a reliable
  ring drops a subscriber that, with data still pending, accepted no data for
  `WIRED_MOQTREL_STALL_MS`). These resets are counted only while the session
  has a backpressure set, and they take the place of the resets that moqtail's
  own discard timeout would trigger. Source: `moqtssts_run.c` header comment.
- **The default algorithm's estimate follows the congestion window** —
  Affects: subscribers whose quality should rise quickly. The budget is the
  stricter of `ssts_cap_kbps` and the subscriber connection's delivery-rate
  estimate: BBR's bottleneck bandwidth (BBR is the congestion controller
  that models the narrowest link), else cwnd (congestion window: how much
  the sender may have in flight) divided by the smoothed RTT. It is not a
  probe. A subscriber that only receives the lower member keeps the
  connection app-limited, so the estimate can rise slowly and the split may
  stay low until the window grows. Before the first RTT sample the estimate
  is unknown and only the cap applies. Source: `wired_server_wt_est_kbps`.
- **SWITCHING_SET_ASSIGNMENT in PUBLISH_OK / REQUEST_OK is unsupported** —
  Affects: moqtail clients that put it there. moqtail accepts it in those
  messages, but this hub accepts it only in SUBSCRIBE and in a REQUEST_UPDATE
  of a subscription. Elsewhere it is not an allowed parameter (a decode
  violation). Source: `MOQCTL_PARAM_RULES`.
- **Fills and FETCH are not gated by SSTS** — Affects: members that also ask
  for history. A member joining in the middle of a Group (by SUBSCRIBE or
  REQUEST_UPDATE) gets the track's largest Group decided at once (its
  recorded decision wins), so the reliable ring replays it. A fill or FETCH,
  however, serves every Group regardless of the set's decisions. Source:
  `moqtss_on_subscribe`.
- **No switch prompt, GOP extension or latency budget** — Affects: nobody
  today. These ideas come from the "Art of the Switch" talk but are not in
  moqtail's code either, so they are out of scope.
- **SWITCH_FROM and SSTS do not combine on one subscription** — Affects:
  clients that try both. A SWITCH_FROM naming a member of a switching set is
  refused with INVALID_SWITCH (0x32). Use the set (sender-side) or explicit
  switches (receiver-side), not both. Source: `moqtswitch.c`.
- **SWITCH_FROM with FILL_PARAMETERS is refused** — Affects: clients that
  want history on the new track. The refusal is INVALID_SWITCH (0x32). A
  switched-to subscription starts at the boundary Group G and gets no
  history fill. Source: `test_moqtrun_switch_fill_refused`.
- **Hard mode cuts when Group G reaches the hub, not the subscriber** —
  Affects: Hard switches on a congested connection. The old subscription
  ends once the new track's Largest Group is at least G (by stream or
  datagram). If the hub cannot open the new Group-G stream to the subscriber
  yet (no stream credit, or a backlog), the old in-flight Groups are reset
  first, so there is an explicit gap. The new Group G then arrives through a
  late open and may lose its first Object. Source: `moqtswitch.c`.
- **A suspended subscription holds its slots** — Affects: hubs near their
  subscriber or request capacity. Without Publish Done (flag 0x80), the
  switched-away subscription stays (FORWARD 0, request stream open) so that
  it can be switched back. It keeps its subscriber slot and request stream
  until the subscriber cancels it or the session closes. Source:
  `moqtsw_suspend`.
- **Only request-stream subscriptions can join a switching set** — Affects:
  clients that subscribe on the control stream or to the hub's own tracks.
  A SWITCHING_SET_ASSIGNMENT on a control-stream SUBSCRIBE (one that can
  silently re-attach when its publisher returns), or on a SUBSCRIBE to the
  hub's own tracks, is refused with UNSUPPORTED_EXTENSION (0x33). Draft-22
  request-stream subscriptions end with PUBLISH_DONE when the publisher goes
  away, so their set membership never outlives the track. Source:
  `test_moqtrun_ssts_ctrl_subscribe_refused`.
- **Switching during a failover wait** — Affects: switched or set-member
  subscriptions whose publisher drops (see the failover entries under
  [MoQT relay (hub)](#moqt-relay-hub)). The old side of a SWITCH_FROM never
  waits: it ends at once, so a re-attach cannot feed both sides the same
  Group. A waiting new side whose old side ended in the meantime is released
  from the boundary when it re-attaches. A member of a switching set that is
  re-attached leaves its set and gets every Group until a REQUEST_UPDATE
  assigns it again. That assignment must come after the re-attach: one sent
  while the subscription still waits is refused as a failed update, which
  ends the subscription. Source: `moqtrun_rp_wait`,
  `moqtrun_reattach_one_sub`.
- **A member lagging more than 5 Groups is decided again** — Affects:
  members that deliver very late Groups. Decisions are kept per set for its
  newest Group minus 5 (moqtail's window). A member that delivers a Group
  older than that gets a fresh decision, so such a late Group can come from
  both members. Source: `test_moqtrun_ssts_lag_outside_window`.
- **A cross-publisher switch can lose its boundary across a reconnect** —
  Affects: a rare combination of a cross-publisher switch, a reconnect and a
  filter update. If the old track's publisher reconnects while the
  switched-to track's publisher (a different session) stays live, the new
  subscription is released from its boundary before the old one
  re-attaches. A later LOCATION_FILTER update on the new subscription is
  then no longer clamped to G, so a few Groups could reach the subscriber
  from both tracks. Source: `moqtsw_old_alive`.
- **Busy-shed can downshift without network congestion** — Affects:
  high-bitrate tracks in a switching set. The lossy relay resets a
  subscriber stream after `WIRED_MOQTRUN_RESET_AFTER_BUSY` (8) refused
  rounds, a threshold tuned for 20 ms voice, and every such reset feeds
  backpressure. In browser runs, a 1080p screen share at about 3 Mbps on
  loopback hit it in 2 of 3 runs, so Auto went to the low member with no cap
  in place. A shed Group of a switching-set member is not re-opened midway;
  a track outside any set (voice) still is. Source:
  `moqtrun_relay_shed_one`.
- **A newer Group cuts only the newest older stream** — Affects:
  subscribers on the lossy path of a hub with `newest_group_only` set (off
  by default; the moqt_chat example sets it). The lossy relay remembers one
  stream per subscription. When a newer Group opens, it resets that stream and any
  older Group stream whose publisher is still sending. Another Subgroup of
  an older Group that the publisher already ended still drains. These resets
  do not feed backpressure, because the hub cannot tell whether the stream
  still had unsent bytes. Source: `moqtrun_sub_note_open`.
- **Variants must share Group numbers** — Affects: publishers of variant
  tracks. The boundary rule assumes aligned Group IDs across the variant
  tracks. The hub does not check this.
- **Soft give-up is fixed** — Affects: Soft switches to a track whose next
  keyframe is far away. The hub waits `WIRED_MOQTSW_SOFT_WAIT_MS` (4000 ms,
  two moqt_chat keyframe Groups) of wall-clock time after the switch. It
  gives up only while nothing of the old subscription below G is still live.
  Groups of the old subscription that arrive later are dropped. Source:
  `WIRED_MOQTSW_SOFT_WAIT_MS`.

## Raw-QUIC MoQT

MoQT can also run directly over QUIC, without HTTP/3 or WebTransport, using
the ALPN `moqt-18`, `moqt-19` or `moqt-22`. These raw sessions share the hub
with WebTransport sessions (`wired_moqt_on_session_raw`). It is verified
in-process, against pinned xquic and moqtopus bytes, and in the project's
MoQT interop runs; see [Testing](#testing-and-verification-gaps).

- **raw_policy accepts every well-formed PATH/AUTHORITY** — Affects: raw
  deployments that need access control. The hub's `raw_policy`
  (`moqraw_accept_all`) validates only the RFC 3986 shape
  (MALFORMED_PATH 0x9 / MALFORMED_AUTHORITY 0x1A). Any well-formed value is
  accepted unless the app installs a hook. Source: `moqraw_accept_all`.
- **GOAWAY New Session URI is empty on raw QUIC** — Affects: mixed
  deployments that must send a raw client to a different target. The app's
  one URI names the WebTransport endpoint, so raw sessions get an empty URI,
  which means "reuse the current one". Source: `moqtrun_goaway_uri`.
- **0-RTT refused on a raw ALPN** — Affects: raw clients that want 0-RTT
  (sending data in the first flight of a resumed connection). A raw-QUIC
  connection is never admitted in 0-RTT (d18 3.3.1 / d22 6.3.1 make this a
  relay MAY). Its NewSessionTicket omits the early_data extension so a
  resuming client does not attempt it. Source: `ticket_max_early_data`.
- **Close reasons bounded by one minimum-size packet** — Affects: nobody in
  practice. The hub's application CONNECTION_CLOSE (0x1d) reason phrase is
  cut (at a UTF-8 boundary) to `SRVRUN_RAW_CLOSE_REASON_MAX` = 1148 bytes,
  which is what fits next to the frame overhead in a 1200-byte datagram.
  Every kept WT close message (at most 1024 bytes) goes out whole. Source:
  `SRVRUN_CLOSE_PL_MAX`.
- **9 client uni streams per connection** — Affects: raw publishers with
  many Subgroups open at once. Raw MoQT uses one uni stream per Subgroup.
  The server advertises 9 client uni streams and has a receive slot, with
  its own `WIRED_SRVLOOP_WT_BUF_CAP` window, for each of them
  (`WIRED_SRVLOOP_MAX_WT_UNI_STREAMS` = 9). The same 9 slots serve
  WebTransport: over HTTP/3, 3 of them go to the client's control and QPACK
  streams, leaving 6 for WT data. Raw sessions get all 9. Source:
  `WIRED_SRVLOOP_MAX_WT_UNI_STREAMS`.
- **Hub full on raw** — Affects: raw clients joining a full hub. With no free
  session slot, a raw session is closed with INTERNAL_ERROR at once. Source:
  `moqtrun_refuse_session`.
- **No raw MoQT client role** — Affects: apps that want wired to connect out
  over raw QUIC. wired has no raw-QUIC MoQT client; only the relay role is
  registered in the interop runner. Client roles in general are listed under
  [Out of scope by design](#out-of-scope-by-design).

## WebTransport

- **Control stream backlog capped** — Affects: peers that send large control
  frames. The unparsed backlog of the peer's control stream must fit
  `WIRED_SRVLOOP_CTRL_BUF_CAP` (512 bytes); a larger frame or gap closes the
  connection with H3_EXCESSIVE_LOAD. Source: `priority_ctrl.c`.
- **Out-of-order gap ranges** — Affects: nobody at the targeted sizes. A WT
  stream tracks at most `WIRED_SRVLOOP_WT_MAX_RANGES` (8) disjoint gaps in
  one window; more are coalesced or dropped. Source: `wt_range_overlaps`
  (ponytail).
- **Pending broadcast datagrams per connection** — Affects: apps that
  broadcast datagrams in bursts. A connection queues `SRVRUN_DG_PENDING_Q`
  (4) datagrams of up to 1200 bytes; a full queue refuses the newest. Source:
  `SRVRUN_DG_PENDING_Q`.
- **Pre-establishment datagram buffering is bounded** — Affects: clients that
  send datagrams before the session is established.
  `WIRED_WT_MAX_BUFFERED_DATAGRAMS` (4) datagrams of up to
  `WIRED_WT_BUFFERED_DATAGRAM_CAP` (256) bytes are kept; longer ones are
  dropped whole, never truncated. Source: `WIRED_WT_BUFFERED_DATAGRAM_CAP`
  (ponytail).
- **Datagram drain is a fixed slice, not congestion-controlled** — Affects:
  apps that send many queued datagrams. Each drain sends at most
  `SRVRUN_DGRING_DRAIN_MAX` (16) datagrams or `SRVRUN_DGRING_DRAIN_BYTES`
  (3000) bytes every `SRVRUN_DGRING_DRAIN_MS` (5 ms), about 4.8 Mbps. Source:
  `SRVRUN_DGRING_DRAIN_MAX` (ponytail).
- **MAX_DATA ignores control-stream bytes** — Affects: nobody at normal
  sizes. MAX_DATA is the connection-wide flow-control limit. The ceiling
  counts WT streams, streamed request bodies, CONNECT-stream capsules and the
  peer's QPACK encoder stream. Control-stream and buffered request bytes
  ride on the initial 10 MB (`STP_DEFAULT_MAX_DATA`). Source:
  `srvrun_grant_conn_credit` (ponytail).
- **Concurrent WT sessions per connection** — Affects: clients that open
  many sessions on one connection. The limit is `SRVRUN_MAX_WT_SESSIONS` (2)
  per connection, `SRVRUN_MAX_WT_SESSIONS_GLOBAL` (64, equal to
  `WIRED_CONNTABLE_CAP`) across all connections, and
  `SRVRUN_MAX_WT_SESSIONS_PER_WINDOW` (10) new sessions per connection per
  second. Source: those macros.
- **Server-initiated stream blocked: the caller retries** — Affects: apps
  that open server streams. When the peer's stream limit is reached, the open
  function (`wired_server_wt_open_uni` and its siblings) returns -1, and
  WT_STREAMS_BLOCKED is sent only for the stream-count cause. Retrying is the
  caller's job. Source: `srvrun_wt_streams_blocked_owed`.
- **No HTTP/2 or capsule-only WebTransport** — Affects: clients without
  HTTP/3. WebTransport over HTTP/2 and HTTP Datagrams over HTTP/1.x or
  HTTP/2 are not implemented. There are also no rate-limit headers and no
  re-expression of flow control by intermediaries. Source:
  [draft-webtrans-http3.md](draft-webtrans-http3.md),
  [rfc9297.md](rfc9297.md) Out of scope.
- **`h3_tunnel_relay` only flips state** — Affects: apps that use a CONNECT
  tunnel. The raw byte relay of the tunnel (over h3 DATA frames) is the
  application's job. Source: `h3_tunnel_relay` (ponytail).
- **Capsule-Protocol header not generated or parsed** (RFC 9297 3.4) —
  Affects: nobody for WebTransport, which does not require it. This is a
  deliberate scope decision. Source: [rfc9297.md](rfc9297.md) Out of scope.
- **Capsule-only HTTP Datagram fallback absent** — Affects: paths without
  QUIC DATAGRAM support. QUIC DATAGRAM is assumed. Source:
  [rfc9297.md](rfc9297.md).

## HTTP/3 and QPACK

QPACK is the header compression of HTTP/3. It can keep a dynamic table of
recently sent headers, updated over its own encoder and decoder streams.

- **Origin server only** — Affects: apps that need a proxy or push. There is
  no CONNECT proxying to TCP (only Extended CONNECT per RFC 9220), no server
  push (PUSH_PROMISE, push-ID priority). Client roles are listed under
  [Out of scope by design](#out-of-scope-by-design). Source:
  [rfc9114.md](rfc9114.md), [rfc9218.md](rfc9218.md),
  [rfc9220.md](rfc9220.md).
- **QPACK dynamic table on the receive side only** — Affects: bandwidth of
  response headers, and peers whose encoder stream is lost early. In short:
  responses never reference the dynamic table, so their headers are a little
  larger. Request headers can use the client's dynamic table, up to 2016
  bytes. A request that would have to wait for a table update fails instead
  of waiting.

  The details: the decoder advertises capacity 2016 (`QPACK_DYN_MAX_CAPACITY`)
  and `SETTINGS_QPACK_BLOCKED_STREAMS 0`. It applies the peer's encoder stream
  and sends Section Acknowledgments, Stream Cancellations and Insert Count
  Increments on a decoder stream opened at id 11, so the first application uni
  stream is 15. It never blocks a stream: a section that needs inserts not yet
  received is `QPACK_DECOMPRESSION_FAILED`.

  The encoder stream is reassembled in a 48 KB window equal to its stream
  credit, re-granted as it is consumed. Bytes that arrive before a stream's
  type byte are held while only one uni stream's type is unknown (a stream
  whose type is known is never held). When two are lost at once, the
  second one's early bytes are dropped. If that is the encoder stream, no
  later insert applies, and the peer's encoder is left with the static table
  and the entries acknowledged before.

  A trailer section on a request whose body streams to the application
  (`on_body`) is skipped unacknowledged, which keeps its references pinned
  for the connection's life. The acknowledgment queue holds one step's
  worth; it drops entries only if the peer grants the decoder stream no
  credit. The server's own encoder table stays at capacity 0, and response
  strings are never Huffman-coded. Source: [rfc9204.md](rfc9204.md),
  [rfc7541.md](rfc7541.md) Out of scope.
- **HTTP semantics are the application's** — Affects: every HTTP app. The
  SDK does not handle trailers, `Date`, conditional or range requests,
  content negotiation or TRACE; field values are passed to the application
  verbatim. Source:
  [rfc9110.md](rfc9110.md) Out of scope.
- **Response body cap** — Affects: handlers with large responses. A fixed
  response row holds `WIRED_SRVRUN_RESP_MAX` (16384 bytes) minus the
  512-byte header room (`SRVRUN_RESP_HDR_ROOM`), so 15872 body bytes per
  round. Larger bodies use a `srvbigbuf` row (the large-response buffer
  pool) or streaming
  ([guide](https://hakkadaikon.github.io/wired/guide/en/h3/streaming/)). The
  grid is 64 connections x 40 response slots (`SRVRUN_RESP_SLOTS`) x 16 KiB,
  about 40 MiB of BSS (zero-initialized static memory), multiplied by the
  worker count under `--cores N`. The low-level handler body cap is
  `WIRED_SRVLOOP_BODY_MAX` (1024). Source: `WIRED_SRVRUN_RESP_MAX`,
  `WIRED_SRVLOOP_BODY_MAX` (ponytail).
- **Request buffer limited to `BODYWIN_CAP` (2048)** — Affects: clients that
  send request bodies to a handler without `on_body`. A buffered request that
  fills the window without FIN is answered with 413 or 431, including one whose
  FIN comes in a later empty frame ("window stuck"). A byte past the window is
  past the stream credit and closes the connection with FLOW_CONTROL_ERROR. Use
  `on_body` for larger bodies
  ([guide](https://hakkadaikon.github.io/wired/guide/en/h3/post-body/)). Source:
  `route_window_stuck` (ponytail).
- **Abort retransmit table is fixed-size** — Affects: nobody in practice. A
  stream abort is a RESET_STREAM or STOP_SENDING frame. `SRVRUN_RST_RETX` keeps
  one abort per stream the connection can track (93). If more than that many
  aborts are unacknowledged within one RTT, the excess ones are sent once and
  never retransmitted (RFC 9000 13.3). Source: `srvrun_rst_keep` (ponytail).
- **A request that cannot be decoded is aborted, not answered** — Affects:
  clients that send malformed or oversized HEADERS. A request stream whose
  whole HEADERS frame cannot become a request is reset with H3_MESSAGE_ERROR
  plus STOP_SENDING, without waiting for a FIN. One that ends before its
  HEADERS frame is whole gets H3_REQUEST_INCOMPLETE. No 4xx status is sent,
  and a HEADERS frame past this decoder's local limits gets H3_MESSAGE_ERROR
  like a malformed one. Its slot and bidi stream credit are returned. The
  same happens for a request stream the peer resets while it is still being
  received, or before any of its data claimed a slot. Source:
  `connect_headers_complete`, `route_note_incomplete_append`,
  `reset_request_stream`, `srvrun_abort_incomplete_reqs`,
  `srvrun_free_reset_reqs`.
- **STOP_SENDING before the response starts is not remembered** — Affects:
  clients that cancel a request early. A peer's STOP_SENDING is answered
  with RESET_STREAM (RFC 9000 3.5) only on a send part that already exists
  (a response slot, a WT send slot, a CONNECT stream). One that arrives while
  the request is still being read leaves the later response to run
  normally. Source: `srvrun_answer_peer_stops`.
- **Graceful shutdown is tick-bounded** — Affects: operators who stop the
  server with SIGTERM. The server sends GOAWAY, then waits at most
  `SRVRUN_DRAIN_TICKS` (25) x 200 ms (about 5 s) before it closes. A SIGTERM
  delivered before the handler is installed takes the default action (no
  GOAWAY). See the guide's
  [shutdown page](https://hakkadaikon.github.io/wired/guide/en/ops/shutdown/).
  Source: `srvrun_drain_tick` (ponytail).
- **Spin backoff is count-based** — Affects: CPU use of an idle busy-poll loop
  (a loop that polls the socket instead of sleeping). There is no time-based
  backoff, because the only clock has millisecond granularity. Source:
  `srvpoll_backoff_pause_n` (ponytail).
- **Receive batch** — Affects: throughput at high fan-in. The server reads
  up to `SRVRUN_RX_BATCH` (16) datagrams per `recvmmsg` call, with 32 KB of
  storage per environment. Source: `SRVRUN_RX_BATCH` (ponytail).
- **Idle timeout and eviction grace are fixed** — Affects: long-idle
  clients. `WIRED_SRVRUN_IDLE_MS` is 30000 and `WIRED_SRVRUN_EVICT_GRACE_MS`
  is 1000. Source: those macros.

## QUIC transport

- **Retry token and ticket keys derive from compiled-in seeds** — Affects:
  deployments that need unforgeable Retry tokens or resumption tickets. Both
  keys rotate every `KEYRING_PERIOD_SECS` (2 h), and the previous key still
  opens. But the seeds (`g_srvrun_retry_key`, `g_ticket_key`) are constants
  in the source, so anyone holding the source can derive the keys. Replace
  the seeds before such a deployment. Source: `keyring.h` header comment
  (ponytail).
- **Path validation limits** — Affects: clients that change address (for
  example from Wi-Fi to mobile), and resistance to address spoofing. A QUIC
  server checks a new client address by sending a PATH_CHALLENGE and waiting
  for the matching PATH_RESPONSE. Two PATH_CHALLENGEs are tracked at once
  (the new path and the path left), plus the last validated path. A probe
  from a new path is answered and validated only when a slot is free, and
  ignored otherwise. RFC 9000 8.2.2 says every PATH_CHALLENGE MUST be
  answered, and an attacker relaying genuine packets from other addresses
  can keep both slots busy. Only the first two PATH_CHALLENGEs of a packet
  are answered.

  When a path's validation is re-armed (for example, because a second move
  left that path), a fresh challenge starts, so a late response to the
  earlier one is not matched; the path validates on the next one. An
  off-path copy of a genuine new packet still moves the send path until that
  path's validation times out
  and the server reverts (RFC 9000 9.3.3 calls this defense imperfect). The
  server does not reset congestion control or RTT when the send path
  changes, and does not apply the anti-amplification limit (send at most
  three times what was received) to an unvalidated path. Source:
  `srvrun_path_*`, `pathsel`.
- **Peer connection IDs** — Affects: clients that migrate more than once. A
  connection ID (CID) is the label that lets a QUIC connection survive an
  address change. The server keeps at most two of the client's CIDs (the
  default active_connection_id_limit; it advertises no higher one), so a
  probe answered from a new socket and a later migration compete for the one
  spare. With no spare ID left, the old one stays in use until the peer
  issues more. Each RETIRE_CONNECTION_ID is sent once and not retransmitted,
  and a full retire queue drops the frame, so the peer keeps that ID active.
  Stateless reset tokens from NEW_CONNECTION_ID are not kept. A repeated
  NEW_CONNECTION_ID for an ID the server retired more than 64 sequence
  numbers above Retire Prior To is held again. Source: `peercid_owe`,
  `peercid_bit` (ponytail).
- **ECN-failed connections lose GSO** — Affects: send throughput on networks
  that break ECN (Explicit Congestion Notification marks in the IP header).
  A connection whose ECN validation failed sends Not-ECT through a
  per-datagram TOS cmsg, one `sendmsg` per packet, with no GSO (kernel
  segmentation offload) batching. AF_XDP (the kernel-bypass driver) never
  marks. ECT(1) is never sent. Source: `srvrun_ecn_unmarked` (ponytail).
- **No kernel-fallback paths for socket options** — Affects: apps that call
  the `udp.h` socket helpers directly. The helpers for `IP_TOS`/`IP_RECVTOS`
  and the `IP_MTU_DISCOVER`-style PMTU probe option return the setsockopt
  error and offer no fallback. `wired_server_run` calls them best-effort and
  binds anyway, so on a kernel that rejects them the server runs without ECN
  marking/reading or without kernel PMTU suspension. Source:
  `wired_udp_ect0_enable` and its siblings in `udp.h` (ponytail),
  `srvrun_listen`.

The next three entries concern lower-level entry points. The server that
`wired_server_run` builds (the one the guide uses) does not run the
connrunner loop, connio or `appdata_recv`, so they matter only if you call
those directly.

- **Time-threshold loss detection is off in the connrunner loop** — Affects:
  users of the connrunner loop only. `CONNRUNNER_NO_RTT_DELAY` makes loss
  detection purely packet-threshold there (RFC 9002 6.1.1). The server path
  (srvrun) uses its own recovery. Source: `CONNRUNNER_NO_RTT_DELAY`
  (ponytail).
- **`connio` always marks its sends as ack-eliciting** — Affects: users of
  connio only. The flag is hard-set to 1, so a send of non-ack-eliciting
  frames only is not classified as such. Source: `connio.c`.
- **`appdata_recv` has no packet-number history** — Affects: users of this
  one-shot entry only. It passes largest_pn 0; full packet-number recovery
  is the job of the srvloop path. Source: `app_recv.c` (ponytail).
- **Key Update limit stalls instead of closing** — Affects: very long
  connections. AEAD keys have a confidentiality limit (how much data one key
  may protect). A limit hit while the previous key update is still
  unconfirmed stalls sends; in practice the idle timeout fires first.
  Source: `ku_limit_gate` (ponytail).
- **Linear connection table** — Affects: servers that would need more than
  64 connections. `WIRED_CONNTABLE_CAP` is 64 slots, searched by linear
  scan. Source: `conntable.h` header comment (ponytail).
- **0-RTT replay ring** — Affects: multi-process deployments that accept
  0-RTT. `ZERORTT_SEEN_CAP` holds 4096 fingerprints, and the oldest is
  evicted. There is no persistence or cross-process sharing. Replay of an
  evicted entry is bounded by the ticket lifetime. Source: `zerortt_seen.h`
  (ponytail).
- **PTB (ICMP) ignored** — Affects: paths with a smaller MTU than probed.
  DPLPMTUD (finding the largest packet size by sending probes) is
  probe-based only (the RFC 8899 4.6.1 option). The initial window uses a
  fixed 1200-byte maximum datagram. There is no PLPMTU sharing across flows
  and no ERROR/DISABLED phase. Source: [rfc8899.md](rfc8899.md),
  [rfc9000.md](rfc9000.md), [rfc9002.md](rfc9002.md) Out of scope.
- **Optional RFC 9002 heuristics not implemented** — Affects: recovery
  behavior in unusual loss patterns. These are MAY items: re-establishing
  min_rtt at other times (5.2; the SHOULD reset on persistent congestion is
  done), RTT reuse across connections, loss leniency for pre-key packets,
  the RFC 7661 window update, and a CE-marking probe. Persistent congestion
  (7.6.2) is declared conservatively: it is not declared for a loss period
  that overlaps an ACK from an earlier ACK frame, or that is checked against
  a step whose ACK ranges filled the 32-entry list. Under BBR, persistent
  congestion leaves cwnd (the congestion window) to BBR's model. Source:
  `srvrun_loss_unbroken` (ponytail),
  [rfc9002.md](rfc9002.md) Out of scope.
- **IPv4/UDP/IP details** — Affects: unusual IP traffic. There are no IP
  options, no fragmentation or reassembly and no ToS use. TTL is fixed at 64
  on the AF_XDP path, and the UDP source port 0 case is not handled. Source:
  [rfc791.md](rfc791.md), [rfc768.md](rfc768.md) Out of scope.
- **Connection migration interop** — Affects: clients that migrate. The
  [interop page](../interop.md) records `connectionmigration` as partial: it
  passes against ngtcp2, and the quic-go client never triggers a path
  change. The quic-go client does not support the `ecn` and `v2` testcases;
  both pass against ngtcp2 (`v2` also against picoquic).
- **Handshake keys are kept after the handshake is confirmed** — Affects:
  anyone who relies on RFC 9001 key discard, for example to limit what a
  later memory leak of the process exposes. RFC 9001 4.9.2 says an endpoint
  MUST discard its Handshake keys once the handshake is confirmed. The
  server keeps them, and still decrypts Handshake packets with them
  (`wired_srvloop_open_keys` has no confirmation check). Only
  `wired_server_close` wipes them (`keysched_wipe`), and the
  `wired_server_run` loop does not call it, so the keys stay in the
  connection slot until the slot is reused for a new connection. Source:
  `wired_srvloop_open_keys`, `wired_server_close`.
- **An Initial re-initializes a confirmed connection's slot** — Affects:
  every confirmed connection, because its CID is visible on the wire. An
  Initial packet whose destination CID matches a confirmed connection is
  treated as a fresh connection attempt: the slot is cold-started for a new
  handshake, which replaces the confirmed connection's state. Anyone who can
  see the CID can therefore send such an Initial. (Before confirmation the
  same Initial is handled as a retransmit instead.) Source:
  `srvrun_reinit_ok`, `srvrun_serve_boot`.

## TLS 1.3

- **An expired ticket still resumes** — Affects: the ticket lifetime and
  the resumption cap (`SRVLOOP_RESUMPTION_MAX_SECS`). The server checks a
  ticket's issued_at + lifetime only before accepting 0-RTT; a plain 1-RTT
  resumption accepts any ticket that opens, however old. Tickets re-issued
  on such a connection stop once the cap is spent, but the presented ticket
  itself can be reused. Source: `sdrv_psk_open_usable`.
- **Ticket replay guard is a ring** — Affects: replay resistance under heavy
  resumption. `TICKETGUARD_CAP` holds 64 fingerprints; an entry evicted by
  newer tickets could be replayed past the window. Source: `ticketguard.h`
  header comment (ponytail).
- **Ticket and Retry-token keys live for one process** — Affects:
  resumption and address validation across a restart, and across servers
  started separately behind one address. Both seeds are drawn from the
  CSPRNG when the server starts (forked `srvworkers` and `srvthreads`
  workers share one draw), so a ticket or Retry token issued before a
  restart, or by another independently started server, no longer opens.
  Source: `srvkeys.h`.
- **0-RTT replay tracker shares one spinlock** — Affects: `srvworkers`
  deployments. The tracker is shared across forked workers through a
  `MAP_SHARED` mapping, guarded by one spinlock over a bounded scan; a
  worker killed inside that scan (SIGKILL at that instant) would leave
  0-RTT acceptance blocked in every worker until restart. Source:
  `zerortt_seen.c` (ponytail), `sdrv_zerortt_share`.
- **Cipher suites: preference AES-128-GCM, ChaCha20-Poly1305, AES-256-GCM**
  — Affects: clients that insist on their own suite order. All three TLS 1.3
  AEAD suites are negotiated, in the server's order rather than the
  client's. `TLS_AES_256_GCM_SHA384` has no recorded interop run against an
  independent peer yet, and `tls_exporter` (RFC 8446 7.5) still hashes its
  context with SHA-256 under it (it has no production caller). CCM suites
  are refused. Source: `cipher.c`, [rfc8446.md](rfc8446.md) 8446-099.
- **No client authentication or server-side CertificateRequest** — Affects:
  apps that need mutual TLS. The server never requests client certificates
  (the codec exists but is not wired). There is no post_handshake_auth, no
  OCSP/SCT, no `certificate_authorities` selection and no FFDHE, and external
  PSKs ("ext binder") are unsupported. Source: [rfc8446.md](rfc8446.md) Out
  of scope.
- **TLS extensions not shipped** — Affects: clients that need these
  extensions. max_fragment_length, client_certificate_url, trusted_ca_keys,
  truncated_hmac and status_request are not implemented. Source:
  [rfc6066.md](rfc6066.md).
- **ClientHello and Retry scratch buffers are MTU-bounded** — Affects:
  memory footprint, and ClientHellos larger than two Initial packets. The
  boot-stage accumulator is about 4 KB per connection slot (64 slots, in
  BSS) and spans two Initials, enough for a post-quantum-sized ClientHello.
  The `retry_tag` pseudo-packet scratch is 1521 bytes. Source:
  `wired_srvboot_acc` (ponytail), `retry_tag.c` (ponytail).
- **Client / server pump shortcuts** — Affects: users of these legacy entry
  points only; the `wired_server_run` server does not use them.
  `wired_server_pump` hands a raw datagram to `wired_server_feed`, and
  `client_build_initial` builds the ClientHello, both without on-wire AEAD
  Initial protection. Source: `wired_server_pump`, `client_build_initial`
  (ponytail).
- **Certificate path processing** — Affects: apps that verify certificate
  chains with these features. iPAddress name-constraint subtrees are not
  applied to an IP-literal CN. There is no CRL, OCSP or other revocation
  check, no policy mapping, no IDN processing, and no SRV-ID or URI-ID
  matching (only DNS-ID dNSName). Source: `nameconstraints.c` (ponytail),
  [rfc5280.md](rfc5280.md), [rfc6125.md](rfc6125.md) Out of scope.
- **Signature algorithms in chains** — Affects: chains with legacy or
  compressed keys. Chains signed with legacy RSA-SHA-1 cannot be verified.
  P-521 issuers verify (ecdsa-with-SHA256/384/512), but only with an
  uncompressed SPKI point; a compressed P-521 key is rejected. Source:
  [BoringSSL vector README](../../tests/vectors/boringssl/README.md),
  `ec_pubkey.c`.

## Cryptography

- **Hash and MAC set** — Affects: only certificate chains signed with SHA-1;
  TLS 1.3 handshakes are not affected. SHA-256, SHA-384 and SHA-512 are
  shipped; SHA-1, SHA-224, SHA-512/224, SHA-512/256 and MD5 are **not**.
  HMAC is SHA-256, SHA-384 and SHA-512 only, so there is **no HMAC-SHA1,
  HMAC-SHA224 or HMAC-MD5**. HKDF is SHA-256 only in the TLS/QUIC profile.
  Source: [BoringSSL vectors](../security/boringssl-vectors.md),
  [BoringSSL vector README](../../tests/vectors/boringssl/README.md),
  [fips180-4.md](fips180-4.md), [rfc5869.md](rfc5869.md).
- **Curves: P-256, P-384 and P-521 only** — Affects: certificates on other
  curves. There is **no P-224, secp224k1, P-192, binary or Koblitz curve**.
  P-384 and P-521 are verify-only (certificate chains; P-521 is not a TLS
  CertificateVerify scheme here). P-256 signs (deterministic RFC 6979,
  `ecdsa_secp256r1_sha256` only). 91 BoringSSL ECDSA vectors are skipped for
  this reason. Source: same as above, [rfc6979.md](rfc6979.md),
  [rfc5480.md](rfc5480.md).
- **No X448, Ed448, Ed25519ctx or Ed25519ph** — Affects: peers that need
  these algorithms. Only X25519 and pure Ed25519 exist. Ed25519 has no
  PKCS#8/OneAsymmetricKey parsing (it takes a raw 32-byte seed) and accepts
  DER only (no BER). Source: [rfc7748.md](rfc7748.md),
  [rfc8032.md](rfc8032.md), [rfc8410.md](rfc8410.md).
- **AEAD: 96-bit nonce and 128-bit tag only** — Affects: nothing in QUIC or
  TLS 1.3. `GCM_NONCE` is 12 bytes and `GCM_TAG` is 16. BoringSSL AES-GCM
  cases with other nonce lengths (5 in AES-128, 2 in AES-256) are skipped.
  There is no GMAC, and short tags are unsupported. Source:
  [BoringSSL vectors](../security/boringssl-vectors.md),
  [sp800-38d.md](sp800-38d.md).
- **AES-192 not implemented** — Affects: nothing in QUIC or TLS 1.3.
  AES-128-GCM and AES-256-GCM (`gcm256.h`, BoringSSL vectors pass) key QUIC
  packet protection. There is no AES-192 and no AES decryption primitive
  (neither GCM nor header protection needs it). Source:
  [fips197.md](fips197.md),
  [BoringSSL vectors](../security/boringssl-vectors.md).
- **RSA: public exponent e = 65537 only, verify only** — Affects:
  certificates with another exponent, and any app that wants to sign with
  RSA. PKCS#1 v1.5 verify accepts SHA-256/384/512 DigestInfo. RSA-PSS is
  SHA-256 with salt length 32 and MGF1-SHA-256 only (TLS 1.3
  `rsa_pss_rsae_sha256`). There is no RSA signing, encryption, key
  generation or private-key type, and no BoringSSL RSA vectors. Source:
  `rsa_verify.h`, `pss.c`, [rfc8017.md](rfc8017.md).
- **ECDSA/ECC key generation not shipped** — Affects: apps that want to
  create keys at runtime. Keys are loaded from certificates or PEM. There is
  no DSA at all. Source: [fips186-4.md](fips186-4.md).
- **Fixed scratch sizes** — Affects: callers of the AEAD primitives with
  large inputs. The ChaCha20-Poly1305 MAC scratch is 3032 bytes
  (MTU-bounded; larger inputs are not supported). GCM re-expands the AES-NI
  key schedule on every call by design. Source: `aead.c`, `gcm.c`
  (ponytail).
- **HKDF, plain SHA-2 digest and RSA lack BoringSSL vectors** — Affects:
  nobody; upstream moved these cases out of its FileTest files. They are
  covered by RFC and FIPS vectors instead. Source:
  [BoringSSL vectors](../security/boringssl-vectors.md).

## Platform / I/O

- **Linux x86-64 only** — Affects: every other OS and CPU. ISA-specific code
  lives in `src/common/arch/x8664/`, and no other ISA is provided (inferred
  from the layout; see [syscalls](../syscalls.md)).
- **`recvmmsg` batch cap** — Affects: callers of the UDP layer that want
  larger batches. `WIRED_RECVMMSG_MAX` is 64, on the stack. Source:
  `WIRED_RECVMMSG_MAX` (ponytail).
- **SO_REUSEPORT is best-effort** — Affects: multi-worker (`--cores N`)
  deployments. `wired_server_run` enables `SO_REUSEPORT` on its socket
  best-effort (`wired_udp_reuseport_enable` in `srvrun_listen`). If the
  kernel refuses it, the error is ignored and a second worker's bind fails,
  so `--cores N` needs a kernel that allows `SO_REUSEPORT`. Source:
  `srvrun_listen`.
- **`printf`-compatible deviations** (`wired_snprintf` family) — Affects:
  apps that log with these functions. `%p` with NULL prints `0x0`. `%f`
  saturates the integer part at 2^64 and caps precision at 40.
  `wired_dprintf` truncates output past 511 bytes. Source: `fmt.h`.
- **AF_XDP path is IPv4 only** — Affects: IPv6 deployments that want the
  kernel-bypass driver. It uses a fixed 20-byte IPv4 header with no options.
  Source: [rfc791.md](rfc791.md).
- **Hub and socket tuning** — see [Capacity limits](#capacity-limits).

## Capacity limits

All of these are fixed-size tables and buffers, most of them in BSS. To
raise one, change the constant and rebuild. The guide's
[Current limits](https://hakkadaikon.github.io/wired/guide/en/concepts/limits/)
page explains the app-facing ones; these tables add the rest and say what
happens when each limit is exceeded. The values here were re-checked against
the `#define`s on 2026-10-15; where the guide shows a different value (for
example `WIRED_MOQTRUN_MAX_TRACKS_PER_PEER` or `WIRED_MOQTRUN_MAX_REQS`),
the value here is the current one.

### MoQT hub

| Constant | Value | Bounds | Effect when exceeded |
|---|---|---|---|
| `WIRED_MOQTRUN_MAX_SESSIONS` | 32 | sessions per hub | no free slot; raw: INTERNAL_ERROR close |
| `WIRED_MOQTRUN_MAX_SUBS` | 31 | subscribers per track | no free subscriber slot |
| `WIRED_MOQTRUN_MAX_FILTER_RANGES` | 4 | Range Filter ranges per request | REQUEST_ERROR INVALID_FILTER |
| `WIRED_MOQTRUN_MAX_REQ_UPDATES` | 4 | unanswered REQUEST_UPDATEs | TOO_MANY_REQUEST_UPDATES (d19+) |
| `WIRED_MOQTRUN_IMPL_MAX` | 64 | MOQT_IMPLEMENTATION bytes | value truncated |
| `WIRED_MOQTRUN_HOLD_BUF` | 2048 | bytes held before SETUP | request reset EXCESSIVE_LOAD, Object dropped |
| `WIRED_MOQTRUN_EARLY_BUF` | 2048 | SUBGROUP bytes before upstream SUBSCRIBE_OK | stream dropped |
| `WIRED_MOQTRUN_GOAWAY_URI_MAX` | 8192 | GOAWAY URI (the spec maximum) | `wired_moqt_goaway` returns -1 |
| `WIRED_MOQTRUN_MAX_RELAYS` | 4 | publisher streams relayed at once per track | stream not relayed, subscribers miss it |
| `WIRED_MOQTRUN_MAX_NAME` | 64 | Track Name bytes | refused (PUBLISH; hub-owned publish returns 0) |
| `WIRED_MOQTRUN_MAX_NS` | 128 | encoded namespace bytes | namespace refused on PUBLISH |
| `WIRED_MOQTRUN_MAX_TRACKS_PER_PEER` | 4 | tracks one session publishes | PUBLISH refused |
| `WIRED_MOQTRUN_MAX_REQS` / `_PER_SESSION` | 96 / 24 | request streams | request stream reset EXCESSIVE_LOAD |
| `WIRED_MOQTRUN_MAX_RDV` / `_RDV_PER_SESSION` | 16 / 4 | rendezvous holds | SUBSCRIBE refused EXCESSIVE_LOAD |
| `WIRED_MOQTRUN_RDV_MAX_MS` | 1500 | rendezvous hold time | hold times out (deviation) |
| `WIRED_MOQTRUN_MAX_UP` | 16 | upstream waiters | waiter refused EXCESSIVE_LOAD |
| `WIRED_MOQTRUN_MAX_FETCHES` (+ fetch_waits) | 8 (+8) | FETCHes and fills served | REQUEST_ERROR INTERNAL_ERROR |
| `WIRED_MOQTRUN_UPFETCH_BUDGET_MS` | 2000 | upstream FETCH leg time | leg ends |
| `WIRED_MOQTRUN_RELAY_FRAG_MAX` | 16384 | torn Object held whole | larger payload passes through |
| `WIRED_MOQTRUN_TRACK_PROPS_MAX` | 32 | Track Properties forwarded | forwarded empty |
| `WIRED_MOQTRUN_RESET_AFTER_BUSY` | 8 | refused rounds on the lossy path | subscriber stream reset |
| `WIRED_MOQTRUN_GOAWAY_GRACE_MS` | 1000 | drain grace | session closed after 1 s, acked or not |
| `WIRED_MOQTRUN_PUBDONE_WAIT_MS` | 2000 | wait after PUBLISH_DONE | remaining streams reset |
| `WIRED_MOQTRUN_SSTS_SETS` | 8 | switching sets | SWITCHING_SET_ASSIGNMENT refused INTERNAL_ERROR |
| `MOQSSTS_MAX_MEMBERS` | 4 | members per switching set | SWITCHING_SET_ASSIGNMENT refused INTERNAL_ERROR |
| `MOQCTL_SSTS_MAX_ALGS` | 4 | SSTS_ALGORITHMS ids | extra ids not kept or sent |
| `WIRED_MOQTSW_SOFT_WAIT_MS` | 4000 | Soft switch wait | gives up on the old track |
| `WIRED_MOQTREL_POOL` | 4 | reliable rings | further reliable tracks use the lossy path |
| `WIRED_MOQTREL_CAP` | 3 x `WIRED_SRVLOOP_WT_BUF_CAP` | ring size | ring wraps |
| `WIRED_MOQTREL_STALL_MS` | 10000 | slow-subscriber wait | slow subscriber shed (reset) |
| `WIRED_MOQTREL_MAX_SUBS` / `_MARKS` | 31 / 8 | ring cursors / arrival marks | no cursor for the subscriber / delivery timeout may fire early |
| `MOQCACHE_OBJ_MAX` | 65472 | cached Object payload | larger Object not cached |

### WebTransport, HTTP/3 and QUIC

| Constant | Value | Bounds | Effect when exceeded |
|---|---|---|---|
| `WIRED_WT_MAX_BUFFERED_DATAGRAMS` / `_CAP` | 4 / 256 | datagrams before session setup | longer datagram dropped |
| `SRVRUN_MAX_WT_SESSIONS` | 2 | WT sessions per connection | session refused |
| `SRVRUN_WTSEND_BUF` | 131072 | staging bytes per WT send slot | larger payload stays a caller-owned view |
| `SRVRUN_DG_PENDING_Q` | 4 | broadcast datagrams queued per connection | newest refused |
| `WIRED_SENDSESS_LOG` | 128 | unacknowledged slices per send session | sent packets go untracked and later look lost; cwnd growth stalls |
| `WIRED_SRVRUN_RESP_MAX` | 16384 | one fixed response round | larger body needs bigbuf or streaming |
| `WIRED_SRVLOOP_BODY_MAX` | 1024 | low-level handler body | body capped |
| `SRVRUN_RX_BATCH` | 16 | datagrams per `recvmmsg` | read in the next batch |
| `WIRED_SRVLOOP_MAX_STREAMS` | 40 | request slots | stream dropped |
| `WIRED_SRVLOOP_MAX_WT_STREAMS` / `_UNI_STREAMS` | 24 / 9 | WT bidi / uni slots | a peer opening more breaks the stream limit (STREAM_LIMIT_ERROR) |
| `WIRED_SRVLOOP_WT_BUF_CAP` | 49152 | per-slot receive window | flow control holds the peer |
| `WIRED_SRVLOOP_MAX_RX_DATAGRAMS` / `_RX_DATAGRAM_CAP` | 256 / 1200 | received datagram queue | datagram dropped |
| `BODYWIN_CAP` | 2048 | request body window | 413/431 or FLOW_CONTROL_ERROR |
| `WIRED_SRVLOOP_CTRL_BUF_CAP` | 512 | control stream backlog | H3_EXCESSIVE_LOAD |
| `SRVRUN_RST_RETX` | 93 | aborts awaiting ACK | excess sent once |
| `SRVRUN_RAW_CLOSE_REASON_MAX` | 1148 | raw close reason bytes | reason cut (unreachable: messages <= 1024) |
| `WIRED_CONNTABLE_CAP` | 64 | QUIC connections | no new connection |
| `ZERORTT_SEEN_CAP` | 4096 | 0-RTT fingerprints | oldest evicted |
| `TICKETGUARD_CAP` | 64 | ticket fingerprints | oldest evicted |
| `WIRED_RECVMMSG_MAX` | 64 | UDP batch size | batch capped |

Notes on the two send-side buffers:

- `SRVRUN_WTSEND_BUF` is the staging area of each server-initiated WT send
  slot (`SRVRUN_WT_SEND_SLOTS` = 17 per connection). A payload up to this
  size is copied in, so the caller's buffer is free when the call returns. A
  larger one stays the caller's own memory (a view) until it is sent. The
  size holds one full WT receive window (49152) plus a held relay fragment
  (16384), so a relayed full-window payload such as a screen-share frame is
  still copied.
- `WIRED_SENDSESS_LOG` is how many sent slices one send session (a response
  or WT send slot) tracks while they wait for acknowledgement. It is sized
  past one bandwidth-delay product of the interop runner's link (about 35
  slices). If it fills, packets already sent are missing from the in-flight
  accounting and later look lost, which stalls congestion-window growth.

## Testing and verification gaps

- **Self-loopback is not interop** — Affects: how to read a green test run.
  wired talking to itself shares the same code on both ends, so a shared bug
  cancels out. By project rule, a feature that touches the wire stays `[~]`
  (indirectly demonstrated) in the ledgers until a test pins it to an RFC
  vector or a real-peer trace; a loopback test alone never marks it done.
- **MoQT interop is the project's own runs** — Affects: readers of interop
  dashboards. The MoQT relay results come from the project's own runs of the
  MoQT interop runner with wired added, published at
  <https://moq-interop-runner-wired.vercel.app>. They are not part of the
  runner's official public results. The QUIC and WebTransport interop status
  is on the [interop page](../interop.md).
- **Valgrind** — Affects: people reading valgrind output. 7 reports on BPF
  attr structs are expected false positives (the kernel zero-fills past the
  given size). 5 reports in `srvworkers_test` depend on timing under
  valgrind.
- **Flaky test** — Affects: CI reruns. The stage CHECKs of
  `sdt_run_wt_stages` (in `tests/app/srvthreads_datagram_test.c`) fail
  rarely. Its handshake CHECK (`hs_ok`) also fails under load: the 5 s
  Initial deadline starts before the worker thread has bound its socket, and
  the server exposes no ready signal to start it from. Source:
  `sdt_retry_initial`.
- **Test builds differ** — Affects: contributors. The shard TUs of
  `just test-fast` can hide a `static`/`typedef` name collision that only the
  single-TU `just test` sees (see [development](../development.md)).
- **Fuzz coverage** — Affects: robustness of the hub loop. `fuzz_moqt`
  covers the codecs, `moqdg` and `moqcache`. The hub run loop (`moqtrun`) is
  not fuzzed, because it is not a codec.
- **Ledger counts** — Affects: the coverage total. 2 requirements are
  untested: MQ22-070a and MQ22-137 (both in
  [draft-moq-transport-22.md](draft-moq-transport-22.md)). The experimental
  track-switching section (MQ22-X13 among them) is not counted. Source:
  [features README](README.md).
- **BoringSSL oracle** — Affects: nobody; listed for completeness. There are
  no failures. Skipped: 91 ECDSA P-224/secp224k1, 12 HMAC MD5/SHA1/SHA224, 7
  AES-GCM cases with non-96-bit nonces, and the 1,000,000-iteration X25519
  case. Source: [BoringSSL vectors](../security/boringssl-vectors.md).

## Out of scope by design

The ledgers mark these as operator, application, client or intermediary
concerns, not SDK code, and exclude them from the coverage count.

- **Client roles** — Affects: apps that need a client. Client-side
  TLS/QUIC/HTTP/3/WebTransport/MoQT behavior is not shipped: client packet
  handling, ClientHello construction, the reaction to Version Negotiation,
  0-RTT client rules, redirect following and WT-Available-Protocols
  construction. The server ignores received Version Negotiation packets.
  Source: [rfc9000.md](rfc9000.md), [rfc9368.md](rfc9368.md),
  [rfc9369.md](rfc9369.md), [rfc8999.md](rfc8999.md),
  [draft-webtrans-http3.md](draft-webtrans-http3.md) Out of scope.
- **Intermediary and proxy behavior** — Affects: deployments that need a
  proxy. HTTP caching, Via/Forwarded, CONNECT to TCP, capsule re-expression,
  QPACK re-encoding, relay-to-relay coordination and Session Migration are
  out of scope. Source: the ledgers.
- **Operator guidance** — Affects: operators. Load-balancer CID routing,
  Alt-Svc, DSCP/QoS, NAT timeouts, key lifecycle, cross-protocol and privacy
  considerations (RFC 9312, RFC 9308, the MoQT security sections) are left
  to the operator. Source: the ledgers.
- **PUBLISH_DONE on the legacy control stream** — Affects: subscribers that
  subscribe on the shared control stream. Such a subscription gets no
  PUBLISH_DONE. The message carries no Request ID in draft-18/19/22 (it
  names its subscription by the request stream it rides), so on a stream
  shared by several subscriptions it cannot say which one ended. The hub
  instead keeps such a subscription and re-attaches it silently when the
  publisher rejoins (`moqtrun_reattach_subs`). Source:
  `moqctl_publish_done`.
- **MoQT URI and name rendering** — Affects: clients. Parsing and
  dereferencing `moqt://` URIs and resolving them through SVCB/HTTPS DNS
  records are client concerns and are not implemented. Names are compared as
  raw bytes, never rendered for humans. Source: the MoQT ledgers.
- **End-to-end Object encryption (SFRAME / Secure Objects)** — Affects:
  apps that need end-to-end encryption. It is an external mechanism. Source:
  [draft-moq-transport-22.md](draft-moq-transport-22.md).
- **Revocation and PKI operations** — Affects: operators who manage
  certificates. CRL, OCSP, CA issuance rules, pinning and the construction of
  reference identifiers are caller policy. Source: [rfc5280.md](rfc5280.md),
  [rfc6125.md](rfc6125.md).
- **Legacy TLS** — Affects: clients without TLS 1.3. TLS 1.2 and earlier,
  the record layer, the KeyUpdate message, EndOfEarlyData and middlebox
  compatibility mode are out of scope; QUIC replaces them. Source:
  [rfc8446.md](rfc8446.md).
- **Re-open conditions recorded for MoQT** — Any of these would bring an
  out-of-scope item back: a peer that speaks only draft-17 or earlier (for
  drafts 14 to 17), a peer that demands raw-QUIC 0-RTT, a deployment that
  needs a per-transport GOAWAY URI, and a need for a wired-side raw MoQT
  client role.

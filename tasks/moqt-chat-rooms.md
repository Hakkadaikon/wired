# moqt_chat: multi-room hub with NIP-98 (no containers)

Status: plan (reviewed once, revised 2026-11-24), not started. This file is
the single source of truth for this work. Mark `[x]` only with a commit hash
and the test that proves it; `[~]` = partly done (say what is left on the
same line). Related: #340 (per-room containers, deferred).

## Decisions (user, 2026-11-24)

- D1 One hub process serves several rooms; a room is a namespace prefix
  `wired/moqt_chat/<room-id>/...`. No containers.
- D2 NIP-98 authentication, carried in MoQT CLIENT_SETUP's
  AUTHORIZATION_TOKEN (browsers cannot add an `Authorization` header to a
  WebTransport CONNECT).
- D3 The creator decides per room whether joining needs NIP-98
  (open / auth-required). Creating always needs NIP-98. Note: Nostr keys are
  free, so "auth-required" means "identity required" (attribution), not an
  invite list.
- D4 A creator must be NIP-98 authenticated AND NIP-05 verified.
- D5 At most 3 rooms per hub (`WIRED_MOQT_CHAT_MAX_ROOMS`, `#ifndef`
  overridable). 4 participants per room.
- D6 A room ends when the host ends it (verified kind 30313
  `status=ended`), 5 h after creation, when one person has been alone for
  30 min, or after it has been empty for a grace period (60 s, so the
  creator's own network blip does not kill it). Ending closes every session
  of the room directly (never GOAWAY / drain, which make clients reconnect)
  with a reason token; clients stop rejoining.

## Open decision (needs the user)

- [x] OD1 (decided 2026-11-24: A now — a Go helper process; B long term, tracked in #341) Who fetches `/.well-known/nostr.json` for NIP-05 (D4)? The
  libc-free SDK has no outbound HTTPS client (no DNS stub, no TCP TLS record
  layer, no HTTP/1.1). Verifying in the browser is not trustworthy (the
  client controls what it reports).
  - A (recommended) a small NIP-05 resolver helper process in Go (Go is
    already in the devShell) next to wired_server, with the SSRF limits in
    P4. The SDK has no AF_UNIX support today (`common/arch/sysops.h` has only
    socket/connect, no sockaddr_un): either add the AF_UNIX wrappers + a
    non-blocking client in `on_step`, or use loopback TCP (any local process
    can reach it).
  - B native in the SDK: DNS stub + TCP + TLS 1.3 client record layer +
    HTTP/1.1 + castore validation; 1-2 weeks, large new attack surface.
  - C HTTP/3-only native fetch; fails for hosts without h3.
  - D operator allowlist of pubkeys or NIP-05 domains by flag; no network,
    no SSRF, also limits squatting; does not literally verify NIP-05 unless
    combined with A for the allowlisted domains.

## Design

### Wire / identity
- NIP-98 event (kind 27235, content "") signed via NIP-07, sent as the
  CLIENT_SETUP AUTHORIZATION_TOKEN: Alias Type USE_VALUE (0x3), Token Type 0
  (out-of-band, draft-23 8.9), value = the event JSON (raw UTF-8; also accept
  `Nostr <base64>` so nostr-tools' nip98 helper can be reused). The first
  USE_VALUE token with Token Type 0 is used; KVP values may be up to 0xFFFF
  bytes, so a ~600-byte event fits in every supported draft (18/19/22/23,
  option type 0x03).
- Tags: `u` = `<public-url><:path>` exactly (the `:path` includes
  `?room=<id>&host=<hex>`), `method` = `CONNECT`; a creator adds
  `["nip05", "<name@domain>"]` and `["wired-room", "<id>", "open"|"auth"]`.
  Adapting NIP-98 (an HTTP auth event) to the WebTransport CONNECT is a
  documented deviation (wire.md).
- Server checks: kind 27235; `created_at` within ±60 s; `u` equals
  `--public-url` + the CONNECT `:path` byte for byte (the hub never sees the
  scheme/authority, hence the flag); `method` = `CONNECT`; NIP-01 id and
  BIP-340 signature valid; id not in the replay cache. A token refused for
  any reason is not recorded (P5 S-048).
- Replay cache: fixed size >= (admission rate limit x 120 s); insert an id
  only after the session is admitted (signature verified AND authorised); when full, refuse new tokens (never
  evict live entries).
- Room id: 16 random bytes, base64url (22 chars), chosen by the creator's
  browser. Share link `?room=<id>&host=<hex>`; the server refuses a join
  whose `host` does not equal the room's host (stops a re-created room id
  from capturing an old link). Space coordinate `30312:<host>:<room id>`;
  NIP-53 `status` = `open` (open room) or `private` (auth-required; NIP-53
  reads "private" as invite-only — documented deviation).
  `NEXT_PUBLIC_NOSTR_HOST` / `_SPACE_D` / `_ROOM_NAME` go away (no-compat).
- Participant ids: per-room pool user1..user4 held by the server. The first
  PUBLISH_NAMESPACE of `wired/moqt_chat/<room>/<id>` claims the id for that
  session; another session claiming it is refused; released on close; in an
  auth room the claim is tied to the session's NIP-98 pubkey.

### Close codes and reason tokens (wire.md table; frontend branches on token)

| Case | Code | Reason token |
|---|---|---|
| Token does not parse | MALFORMED_AUTH_TOKEN 0x16 | `malformed-auth` |
| `created_at` outside window | EXPIRED_AUTH_TOKEN 0x18 | `expired-auth` |
| Signature / u / method / replay / host mismatch / auth room without token | UNAUTHORIZED 0x2 | `unauthorized` |
| NIP-05 not verified | UNAUTHORIZED 0x2 | `nip05-unverified` |
| Room full (5th participant) / id already claimed | UNAUTHORIZED 0x2 | `room-full` / `id-taken` |
| No free room slot / creator limit | UNAUTHORIZED 0x2 | `no-room-slots` |
| No such room (stale link, restart) | UNAUTHORIZED 0x2 | `no-such-room` |
| Room ended | NO_ERROR 0x0 | `room-ended` |
| Replay cache full / per-tick verify cap hit | UNAUTHORIZED 0x2 | `server-busy` (client retries with back-off) [P5 Q2] |

### Admission (async NIP-05)
- The hub accepts SETUP synchronously and the browser sends ~40 requests
  before seeing the server SETUP; a pre-establishment log of 2048 bytes per
  peer overflows. So NIP-05 must not block admission: optimistic create.
  The room starts `verifying`: only the creator is admitted, joiners get
  `no-such-room`-style refusal until verified; a failed or timed-out lookup
  (3 s) ends the room with `nip05-unverified`. The NIP-05 request and its
  verdict carry the room's slot and a per-room-instance nonce set at create
  (never reused) and echo the (domain, pubkey) checked; the hub applies a
  verdict only while that slot is `verifying` with the same nonce and drops
  every other verdict (late, after timeout, after end, slot reused, same room
  id re-created) [P5: G21/G22]. The creator may re-enter a `verifying` room
  on reconnect with a fresh token. NIP-98 itself is verified
  synchronously at SETUP (local CPU only), with a per-tick cap on BIP-340
  verifications (CPU DoS on the single-threaded loop).
- The SETUP token value is copied into fixed per-session storage (1 KiB)
  only while the room is `verifying`.
- Sessions without `?room=` are closed immediately; a SETUP timeout (5 s)
  closes sessions that never send SETUP.

### Namespace confinement (via hooks)

| Request | Hook | Rule |
|---|---|---|
| PUBLISH_NAMESPACE | authorize_namespace | >= 4 fields `wired/moqt_chat/<room>/<id>[/...]`; field 4 is (or claims) the session's id |
| SUBSCRIBE_NAMESPACE / SUBSCRIBE_TRACKS | authorize_namespace | >= 3 fields, field 3 = session's room |
| PUBLISH | authorize_publish | namespace exactly `wired/moqt_chat/<room>` (3 fields), track `<id>` or `<id>/<kind>`; `<id>` is (or claims) the session's id |
| SUBSCRIBE / FETCH / TRACK_STATUS | authorize_subscribe | namespace under `wired/moqt_chat/<room>/` |

Every authorize hook first checks that the session is a current member (not
left/closing) of a `verifying`/`live` room and takes the room id from that
membership; a detached session keeps a stale slot index that must grant
nothing after slot reuse [P5: G28/G31]. One session claims at most one id
[G18]; in an auth room the claim is held only for the session's lifetime (no
reservation across reconnects) [P5 Q3].

REQUEST_UPDATE cannot change names; a joining FETCH inherits its
subscription's grant. Known minor oracle: TRACK_STATUS answers an unknown
name before any check (low value: room ids are random).

### Server (examples/moqt_chat/server)
- Room table `[WIRED_MOQT_CHAT_MAX_ROOMS]`: id, host pubkey, mode,
  state (verifying/live/ending), created_ms, members, id claims[4],
  alone_since_ms, empty_since_ms.
- Anti-squatting: one verifying-or-live room per creator pubkey AND per
  NIP-05 domain [P5: G04]
  (one domain can mint unlimited names); optional operator allowlist of
  domains/pubkeys (flag). Limitations section states that a determined
  attacker with several domains can still hold the 3 slots for 5 h, and that
  a create naming someone else's domain blocks that domain for up to the 3 s
  lookup.
- Lifecycle tick: each tick first ends every room whose timer is due, then
  advances time [P5: TimeWaitsForDueEnds]; lifetime >= 5 h from create
  (clock never rewinds);
  alone >= 30 min, started when the member count becomes 1 and stopped at
  any other count; empty >= 60 s, likewise for 0 members [P5: G20]; host end = a kind 30313 with `status=ended`, `a` = this
  room's space, `pubkey` = host, newest by `created_at` and created after
  the room, from any track of the room (the hub need not know which
  participant is the host) -> end. "Created after the room" compares
  seconds: `created_at >= floor(created_ms / 1000)` [P5 Q5]. Equal
  `created_at` ties go to `ended`. The newest `open` created_at must be
  recorded (P5 survivor: first item in the P6 test list).
- End = set `ending` (refuse joins; authorize nothing in the room), then
  close each member directly with code + reason token and detach it in the
  same step (remove from members, release its id claim); free the slot when
  the member set is empty, exactly once, only from `ending`. An on-close
  callback for an already-detached session is a no-op. Reason:
  `nip05-unverified` when the end reason is NIP-05, else `room-ended`
  [P5: G25/G26/G27/G32].
- A token rejected for any reason is NOT recorded as used (the replay cache
  admits only after authorisation, P2) [P5 Q6]. Durations by flags (`--room-lifetime`,
  `--room-alone-timeout`, `--room-empty-grace`) for e2e.
- `--goaway-uri` keeps `?room=&host=` when redirecting on restart; a restart
  still ends all rooms (in-memory), documented.
- Logging: room create/end with reason, refusal counters per reason; never
  log the token.

### SDK (src/) changes
- Nostr verification (new domain, names `secp256k1_` / `bip340_` /
  `nostrev_` / `nip98_`, grep for collisions): secp256k1 field/group
  (variable time, public inputs only; pubkey must pass lift_x) + BIP-340
  verify; NIP-01 event parser: strict JSON subset with caps, integers only
  (no exponent, sign, leading zero), lowercase hex, decode `\uXXXX` and
  surrogate pairs; canonical serialisation per NIP-01 (escape only
  `\n \" \\ \r \t \b \f`, everything else verbatim) and reject events that
  contain other C0 control characters or lone surrogates (fail closed);
  SHA-256 id check; NIP-98 checker. The lexer is table-driven and split into
  several files (CCN <= 3, nesting <= 2, cognitive <= 4, file volume
  <= 8000).
- CLIENT_SETUP token: `moqctl_setup` gains `has_auth_token` and
  `auth_token_value` (a view valid during dispatch); today
  `moqctl_setup_apply_token` keeps only the alias ref.
- Hooks get the session: add `wired_wt_session*` to all three authorize
  hook types. Callers to update in the same change (no-compat):
  examples/moqt_chat/server/access.c, guide/snippets/moqt-authorize,
  guide/snippets/moqt-discovery, fuzz/fuzz_moqtrun.c, tests/app/moqtrun_*,
  docs/security/*; guide-verify goldens and fuzz-smoke must stay green.
- Admission hook: session + token -> accept / reject (sync); `:path`
  already reaches the app via chat_on_session.
- Hub close with a reason: today `moqtrun_setup.c` closes with an empty
  reason; add a reason argument, callable from the app for any session.
- Per-session on-close callback, safe for an already-detached session.
- An on_step entry that delivers a NIP-05 verdict (slot, nonce, ok), and a
  tick for room timers. No PENDING session state: admission stays sync, the
  pending state is the room's `verifying` [P5].
- Object tap: read-only hook on Objects under a namespace prefix, size cap
  (host's 30313).
- Room-profile capacities as formulas of rooms x 4 with `_Static_assert`s:
  MAX_REQS (12 x 40 = 480 + fills: >= 576, a multiple of 64), per-session
  cap fixed at 48 (not "a quarter of the pool"), MAX_FETCHES and MAX_RDV for
  3 simultaneous joins (3 x 27 fills), RDV_PER_SESSION likewise fixed, cache
  arena shared across rooms (one room can evict another's history —
  documented or partitioned). MAX_SUBS (31), peers, conntable (64) unchanged.
  Deviation (P8): conntable 16, not 64 (the real build was 4; 64 would be
  ~1 GiB BSS).
  Measure BSS and RSS at the end of P3.

### Frontend
- "Create room": NIP-07 login, kind 0 `nip05` present, choose open / auth;
  generate id; sign NIP-98 (nip05 + room tags); connect; copy share link.
- Join from a link: auth rooms sign NIP-98 (and re-sign on every reconnect,
  with the back-off limit, since each token is single-use); open rooms join
  without it.
- Read `WebTransport.closed` in both the connected and the connect-failure
  paths: a resolved close with a known reason token -> final screen, no
  auto-rejoin; a rejected close (network) -> existing rejoin. Today
  `#onClosed` discards the info and reports `disconnected`.
- Parse the room segment in namespace suffixes (moqtClient.ts ~436-441).
- Countdown from the meeting's `ends` (created + 5 h).

### Verification layers
- TLA+ (lifecycle with concurrent joins/leaves, timers and an async
  verdict) BEFORE the hook API is fixed. Invariants: <= 3 rooms; <= 4
  members; no join into an ending room; slot freed exactly once; a join
  resets the alone timer; a late NIP-05 verdict for a closed session/room is
  ignored; id claims unique; verifying room admits only its creator.
- Crypto: BIP-340 test-vectors.csv (all rows), NIP-01 sample events, escape
  corner cases — vectors, not Lean.
- TDD for the rest; fuzz the event parser, the NIP-98 checker and the
  setup-token path.

## Checklist (order: P1 and P2 in parallel, then P5, P3, P4, P6, P7, P8)

### P0 decisions
- [x] OD1 NIP-05 resolver option chosen: A (Go helper) now, B (native SDK HTTPS client) later in #341

### P1 frontend room links (no rebuild per host) — est. 0.5 day
- [x] Room id + host from `?room=&host=`; namespace includes the room;
      suffix parsing updated (9916a40b3; s26-rooms, roomLink tests)
- [x] Remove NEXT_PUBLIC_NOSTR_HOST / _SPACE_D / _ROOM_NAME (docs, e2e, tests) (9916a40b3; s26-rooms, roomLink tests)
- [x] e2e: two rooms on one hub do not see each other (client-side only) (9916a40b3; s26-rooms, roomLink tests)

### P2 Nostr verification in the SDK — est. 3-4 days
- [x] secp256k1 field / scalar / group (variable time, public inputs); lift_x (345a508e1/b2e53dca3/7dcc03d72; wired into the moqt_chat server at 8d72ac8b1)
- [x] BIP-340 verify; all test-vectors.csv rows pass (valid and invalid) (345a508e1/b2e53dca3/7dcc03d72; wired into the moqt_chat server at 8d72ac8b1)
- [x] NIP-01 strict parser (caps, integers, lowercase hex, \u + surrogates) (345a508e1/b2e53dca3/7dcc03d72; wired into the moqt_chat server at 8d72ac8b1)
- [x] NIP-01 canonical serialisation; reject other C0 / lone surrogates (345a508e1/b2e53dca3/7dcc03d72; wired into the moqt_chat server at 8d72ac8b1)
- [x] NIP-98 checker (kind, window, u, method, id, sig, replay cache rules) (345a508e1/b2e53dca3/7dcc03d72; wired into the moqt_chat server at 8d72ac8b1)
- [x] Wiring in tests/run.c (+ fuzz harnesses that include the base .c); (345a508e1/b2e53dca3/7dcc03d72; wired into the moqt_chat server at 8d72ac8b1)
      name-collision grep
- [x] Fuzz harnesses: event parser, NIP-98 checker (345a508e1/b2e53dca3/7dcc03d72; wired into the moqt_chat server at 8d72ac8b1)
- [x] docs/features rows (BIP-340, NIP-01, NIP-98 deviation); vuln-ledger, (345a508e1/b2e53dca3/7dcc03d72; wired into the moqt_chat server at 8d72ac8b1)
      feature-gaps

### P5 TLA+ room lifecycle — est. 1 day
- [x] Requirements into the loop-engineering ledger (tasks/loopeng/MoqtChatRooms.extract.md, S-001..S-052)
- [~] Spec + TLC + mutation oracle; Gherkin (round 3: creation-second ghost, per-term due checks, full oracle rerun on the final text; readback round 2 passed on the round-2 text)

### P3 hub / SDK hooks — est. 2-3 days
- [x] `moqctl_setup` keeps the auth token value (view) -- done (a92990472/90534740d) (test_mthk_setup_keeps_first_token, test_mthk_setup_token_alias_types)
- [x] Session argument on the three authorize hooks; all callers updated
      (examples, guide snippets + goldens, fuzz, tests, docs) -- done (a92990472/90534740d) (test_moqtrun_subscribe_requires_authorization et al.)
- [x] Sync admission hook (session + token); hub close with reason -- done (a92990472/90534740d): hub.admit, wired_moqt_close (callable inside admit / authorize / tap), a closing session is no longer read (requests, Objects, datagrams), legacy sessions closed UNAUTHORIZED while admit is set (the moqt_chat frontend always offers moqt-23 and refuses otherwise: moqtClient.ts:773, :800), full peer table closes INTERNAL_ERROR, the first close's code/reason stand, an authorizer that closes yet grants refuses, a close inside tap stops that delivery's cache and relay (test_mthk_admit_*, test_mthk_close_*, test_mthk_first_close_stands, test_mthk_close_then_grant_refuses, test_mthk_full_hub_closes_wt). On-close / async verdict / timers reuse srvrun's wt_on_session_close and on_step (the app wraps them, as chat_on_session_close / chat_on_step do): no new SDK hook
- [x] Read-only object tap on a namespace prefix (size cap) -- done (a92990472/90534740d) (hub.tap/tap_prefix/tap_max; test_mthk_tap_prefix_and_cap, test_mthk_close_inside_tap); Subgroup streams only, not datagrams
- [x] Room-scaled capacities as formulas + `_Static_assert`s; per-session
      caps fixed -- done (a92990472/90534740d) (moqt_room.h: REQS 576, per session 67 = 40 + 27 joining FETCHes, FETCHES 41, RDV 81, RDV per session 27, GONE 82; test_moqtrun_repath_table_full is skipped in the room profile, unreachable there)
- [~] view-check entries for new stored views (room table, token copy, tap) -- tap_prefix=caller done (a92990472/90534740d); P6 (uncommitted): `views:` tags on chatroom_table / chatroom_who; no token copy is kept (the room copies only the NIP-05 name and the host key), and the room table is not reachable from viewcheck's roots
- [~] Tests per hook; measure BSS / RSS of a 3-room x 4-person hub -- tests done, BSS of wired_moqt_hub 12.43 MB at the room profile (was ~10.47 MB), uncommitted; left: RSS of a running hub
- [x] Docs: guide moqt/authorize (admit, close, tap) and concepts/responsibilities (en/ja), docs/features/draft-moq-transport.md, docs/security/protocols.md -- done (a92990472/90534740d)

### P4 NIP-05 resolver (Go helper, option A) — est. 1-1.5 days
- [x] https on 443 only; no IP literals / ports; domain <= 253, punycode (3f036b8c9; nip05d main_test.go)
- [x] Connect only to the checked address (dial-time check; stops DNS (3f036b8c9; nip05d main_test.go)
      rebinding); refuse loopback, private, link-local, CGNAT, ULA,
      multicast, IPv4-mapped, 169.254.169.254 (e2e flag may allow private)
- [x] No redirects; response <= 64 KiB; JSON parse; 3 s timeout; (3f036b8c9; nip05d main_test.go)
      concurrency cap; positive and negative cache
- [x] Local part `[a-z0-9-_.]` lowercased, `_` root; value = 64-char (3f036b8c9; nip05d main_test.go)
      lowercase hex = pubkey
- [~] Unix socket 0600 (or loopback TCP), unprivileged; build + lint in CI (3f036b8c9, e9dd8806e; CI build+test done — shipping next to the scratch image is left for P6/P8)
      (examples.yml) and shipping next to the scratch image
- [x] Tests: timeout, oversized, redirect, private address, wrong pubkey, (3f036b8c9; nip05d main_test.go)
      missing name

### P6 server rooms — est. 2 days
(All P6 lines: done (0086cdae7..a2b77e6d8; [x] after the P8 room-mode e2e), 2026-11-25. Code examples/moqt_chat/server/room*.c +
room_server.c, tests tests/app/chatroom_test.c (T-01..T-34). Rooms are on only with
--public-url; without it the hub keeps the old unchecked namespace, which the pre-room
e2e use. Wire deviations from the Namespace table: PUBLISH is ns
wired/moqt_chat/<room> + name "<id>[/<kind>]" (the frontend's wire), and a PUBLISH or
PUBLISH_NAMESPACE claims the id. `[x]` after commit + a room-mode e2e (P8).
Review round 1 fixed, round 2 PASS: NIP-05 charset (no request-line injection; nip05d echoes
nothing, so replies still match by order), tap budget 1/room/tick apart from NIP-98's 8,
BIP-340 spent only after nip98_precheck, `open` clamped to now+60 s, --nip05 127/8 only,
"moqt rooms: OFF" log; T-35..T-43.)
- [~] Room table, create / join / refuse rules; host query check -- done (0086cdae7..a2b77e6d8; [x] after the P8 room-mode e2e) (T-01..T-08, T-23)
- [~] Participant id claims per room -- done (0086cdae7..a2b77e6d8; [x] after the P8 room-mode e2e) (T-24)
- [~] Namespace confinement per the table -- done (0086cdae7..a2b77e6d8; [x] after the P8 room-mode e2e) (T-25, T-27; frontend-wire deviation above)
- [~] Optimistic create (`verifying`), async NIP-05 verdict, timeout -- done (0086cdae7..a2b77e6d8; [x] after the P8 room-mode e2e) (T-01, T-09, T-10, T-33; nip05d over loopback TCP, --nip05)
- [~] Anti-squatting (per pubkey, per domain, optional allowlist), SETUP
      timeout, no-room sessions closed, per-tick verify cap -- done (0086cdae7..a2b77e6d8; [x] after the P8 room-mode e2e) (T-26, T-29, T-30; --room-allow)
- [~] Lifecycle: lifetime, alone, empty grace, host end via 30313 -- done (0086cdae7..a2b77e6d8; [x] after the P8 room-mode e2e) (T-11..T-15, T-28, T-32)
- [~] Close with code + reason token; slot freed once; restart semantics;
      --goaway-uri keeps room/host -- done (0086cdae7..a2b77e6d8; [x] after the P8 room-mode e2e) (T-16..T-18, T-31, T-34; new SDK call wired_moqt_goaway_session, test_moqtrun_goaway_session_uri); left: restart semantics in server.md (P8)
- [~] Flags (durations, allowlist, public URL); WIRED_MOQT_CHAT_MAX_ROOMS -- done (0086cdae7..a2b77e6d8; [x] after the P8 room-mode e2e) (room_server.c: --public-url --nip05 --room-lifetime --room-alone-timeout --room-empty-grace --room-allow; no flag test)
- [~] Logging without tokens; unit tests per rule -- done (0086cdae7..a2b77e6d8; [x] after the P8 room-mode e2e) (create/end lines + "moqt rooms: admitted= refused ..." with the 10 s stats line)
- [~] Test first: host end ignores an `ended` older than the newest recorded
      `open` (the newest `open` created_at is stored); P5 survivor -- done (0086cdae7..a2b77e6d8; [x] after the P8 room-mode e2e) (T-12 test_chatroom_host_end_ignores_ended_older_than_open; red without the open_at record)
- [~] Test list from tasks/loopeng/MoqtChatRooms.feature transferred to
      tasks/test-design/ before the P6 tests are written -- done (0086cdae7..a2b77e6d8; [x] after the P8 room-mode e2e) (tasks/test-design/MoqtChatRooms.md)

### P7 frontend — est. 1 day
- [~] Create room UI (NIP-07 + nip05 + mode), share link (2afd44193) -- e2e (P8, uncommitted): open and auth create -> live in s24-s29; reload: 2f3008081 + 24a01413b, {created, mode} per room id in sessionStorage (same-tab reload only; another device needs a hub-sent field); tests: roomLink "P7: a create is kept per room id for a reload of this tab", "P7: works when storage is unavailable", "P7: ignores a stored value with %s", nostrRoomSession "the live meeting ends ROOM_LIFETIME_S after the room was created" (reload step)
- [~] NIP-98 signing for create and auth joins; re-sign on reconnect (2afd44193) -- e2e (P8, uncommitted): every logged-in connect signs (s24/s25/s27); left: no e2e of a reconnect re-sign
- [~] Close-info handling in both paths; final screens per reason token (2afd44193) -- e2e (P8, uncommitted): room-full, unauthorized, no-room-slots (s27), room-ended (s25/s28), no-such-room (s28), nip05-unverified (s29); id-taken now retries the next free id (useIdTakenRetry), new token `replaced`; left: malformed-auth / expired-auth / server-busy only in unit tests (the page refuses an event whose created_at differs, so no e2e for expired-auth); after an id-taken retry s4's voice does not decode again -- open
- [~] Countdown from 30313 `ends` (2afd44193; unit tests) -- not in the e2e; the lifetime end itself is (s28)

### P8 e2e and docs — est. 1 day
- [~] e2e NIP-07 stub + local nostr.json fixture (resolver allowed to reach
      it only in the e2e build) -- done, uncommitted: e2e/lib/roomsE2e.mjs (HTTPS fixture, fake profile relay), nip05d -allow-host (TestAllowHost)
- [~] e2e: create, join, room full, id taken, 4th room refused, auth room
      refuses unauthenticated join, host mismatch, host end, alone timeout,
      empty grace, lifetime (short flags), cross-room isolation -- done, uncommitted (P8 round 2, 2026-11-25; the SETUP-close crash fixed by deferring the hub SETUP until admission): s25 host end, s26 isolation, s27-room-admission (id-taken -> retried as user3, room-full, host mismatch, auth room, no-room-slots), s28-room-timers, s29-room-nip05 x5 all PASS. Evidence tasks/voice-stability/<id>/
- [~] Remove the legacy mode: `--public-url` required (else wired_die),
      delete chat_authorize_room_ns, migrate s24/s25/s26 and the other
      scenarios to create rooms (no-compat; P6 review deviation 1) -- done, uncommitted: default room created by the first client (s1-s23, e2e-load, run-voice, e2e-screen), compose + nip05d service, examples.yml; room profile conntable 4 -> 16 (a 5th joiner was refused at QUIC before room-full); left: s5b/s12/s21 restart semantics (rooms end) not rerun
- [~] P6 review minors: T-35 inputs NUL / non-ASCII / '%'; rename
      g_rooms / g_nip05 / g_room_hub with a module prefix; fold
      nip98_tag_is into nostrev_tag_value if they overlap -- done, uncommitted (chat_rooms_tab/_nip05/_hub; nip98_tag_is = nostrev_tag_count + nostrev_tag_value)
- [~] e2e: nip05d running -> create goes live; nip05d stopped ->
      nip05-unverified after 3 s while other sessions keep running -- done, uncommitted: s29-room-nip05
- [~] wire.md (codes/reasons, NIP-98 and NIP-53 deviations), server.md,
      frontend.md, e2e.md; limitations (restart ends rooms, shared hub
      capacity and cache, squatting with many domains, NIP-05 dependency) -- done, uncommitted (wire.md 2.3, server.md 5, frontend.md 2.1, e2e.md 2.5/3, nip05d README)

#### P8 paused (2026-11-25): s4 state
- Paused for other frontend work; tree builds, all gates green at the pause.
- Symptom: s4-voice-outage-reconnect FAIL "rejoined user3 never decoded
  audio". The crashed user3's stale session holds user3 until the 30 s idle
  timeout, so the rejoin is closed id-taken; useIdTakenRetry then rejoins as
  user4. The second WebTransport opens and is ready, the hub admits it
  (admitted=5, id-taken=1), 7 incoming uni streams arrive, yet
  __decodedFrameCount stays 0 (tasks/voice-stability/s4-voice-outage-reconnect/report.json).
- Hypothesis: the retry path is exit() (leave + teardown, useEndOnRoomClosed)
  followed by connect(); the voice pipeline is not restarted for the new
  session (startVoice skipped or gated: AudioContext / audioContextGate after
  a teardown without a fresh user gesture, or a teardown that lands after the
  new connect).
- Tried: (1) immediate rejoin -> no decode; (2) rejoin delayed 2 s
  (RETRY_AFTER_MS, roomStatus.tsx) so afterRoomEnd's 1.5 s teardown finishes
  first -> still no decode. An auth room (same-key takeover) does not fit s4:
  each client signs its own proxy flow's URL against one --public-url.
- Left: log in the page whether startVoice / the receive pipeline runs after
  the retry; consider retrying without the full exit() teardown (keep the
  audio context, swap only the session); then rerun s4, s27 and s10/s11/s13
  (perf FAILs, suspected host load).

Total estimate: about 11-14 working days (P2 is the largest block).

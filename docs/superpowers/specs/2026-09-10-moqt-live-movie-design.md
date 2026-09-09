# moqt_chat: live delivery of the sample movie over MoQT

Status: approved design, 2026-09-10. Implementation plan follows this spec.

## Goal

`examples/moqt_chat`'s server currently publishes `assets/movie.mp4` as one
static MoQT track: the whole file is framed once and sent to each subscriber
on a single stream. This change delivers the movie the way a live MoQT
stream is delivered: the server paces keyframe-aligned media fragments on a
wall clock as successive MoQT Groups, every viewer sees the same position,
a viewer who joins mid-stream starts at the current Group, and a viewer that
falls behind loses Groups instead of stalling the publisher. The browser
client plays the arriving fragments through Media Source Extensions (MSE).

The sample stays a demonstration of MoQT mechanics on top of this SDK. It is
not a media server: one fixed asset, one bitrate, no catalog, no FETCH.

## Asset

`assets/movie-live.mp4`: a fragmented MP4 (fMP4) derived from
`assets/movie.mp4`, committed to the repository. H.264 High profile video
(854x480, 24 fps, ~1.2 Mbps) and AAC-LC audio, re-encoded with a fixed
2-second GOP so that every fragment starts with a keyframe:

```sh
nix shell nixpkgs#ffmpeg-headless -c ffmpeg -i assets/movie.mp4 \
  -c:v libx264 -preset medium -profile:v high -g 48 -keyint_min 48 \
  -sc_threshold 0 -b:v 1200k -c:a aac -b:a 128k \
  -movflags +frag_keyframe+empty_moov+default_base_moof \
  -f mp4 assets/movie-live.mp4
```

Layout (verified on the generated file): `ftyp` + `moov` = the init segment
(1,260 bytes, no sample tables), then 16 `moof`+`mdat` pairs of about 2
seconds each (10 KB to 405 KB; the last one is short). Both tracks' samples
share each `moof`.

The original `assets/movie.mp4` stays in the repository untouched.

## Track model on the wire

Two hub-owned tracks under the room's fixed namespace `wired/moqt_chat`:

| Track name   | Track Alias | Content | Delivery |
|--------------|-------------|---------|----------|
| `movie/init` | 9           | the init segment (`ftyp`+`moov`) | existing static blob track (`wired_moqt_publish_blob`): one stream, sent once per subscriber on SUBSCRIBE |
| `movie`      | 8           | one media fragment (`moof`+`mdat`) per Group | live track (new): Group g carries fragment `g mod 16` as Group g's only Object (Object ID 0), on its own unidirectional stream, sent when the wall clock enters Group g |

Aliases: chat 0..3, audio 4..7, movie 8, movie/init 9. The frontend's alias
constants and the server's must agree, as today.

Group IDs never wrap. The hub computes the current Group from the wall clock:
`group = (now_ms - t0_ms) / group_ms` with `group_ms = 2000` and `t0_ms` the
time the live track was published. The asset loops (Group g maps to
fragment `g mod 16`), the Group IDs keep increasing, so a subscriber's view
of "largest Group" is always monotonic.

Each Group's stream is one SUBGROUP_HEADER (the same Type 0x70 shape as every
other stream in this sample: PROPERTIES off, Subgroup ID mode 0b00, default
priority, FIRST_OBJECT set; Track Alias 8; Group ID g) followed by exactly
one Object (Object ID Delta 0, Payload Length = fragment length, payload =
the fragment bytes), then FIN.

A subscriber that SUBSCRIBEs `movie` is answered SUBSCRIBE_OK carrying Track
Alias 8 and immediately receives the current Group (the fragment starts with
a keyframe, so playback can begin at once). It then receives every later
Group as the clock enters it. This SDK's SUBSCRIBE_OK codec carries no
Largest Location; the client learns its starting position from the first
Group's header. Filters in the SUBSCRIBE are ignored (behaves as
"largest object / next group").

## Server components

### 1. `src/app/media/mp4frag/` (new domain, prefix `mp4frag_`)

Pure, libc-free walk over an fMP4's top-level boxes:

```c
typedef struct {
  wired_span init;                       /* ftyp..moov inclusive */
  wired_span frags[MP4FRAG_MAX_FRAGS];   /* each moof+mdat pair, contiguous */
  usz        n_frags;
} mp4frag_layout;

/* 1 on success; 0 when the bytes are not an fMP4 of the expected shape:
 * a truncated/oversized box, a moof without a following mdat, more than
 * MP4FRAG_MAX_FRAGS fragments, or no fragment at all. */
int mp4frag_scan(wired_span file, mp4frag_layout* out);
```

`MP4FRAG_MAX_FRAGS` is 64 with the sizing rationale next to it (16 today;
a 2-minute loop at 2 s per fragment). Box sizes of 1 (64-bit largesize) and
0 (to end of file) are rejected as VIOLATION-shaped for this sample's
purposes. Any box other than `moof`/`mdat` after the init segment (for
example `free`, `sidx`) is skipped.

### 2. srvrun additions (`src/app/http3/server/srvrun/`)

- `wired_srvrun_opt.on_step` / `on_step_ctx`: an app callback
  `void (*)(void* ctx, u64 now_ms)` invoked once per loop step from
  `srvrun_step`, after the step's receive/serve work and before the step's
  PTO and datagram drains, with the loop's monotonic clock. Default 0 =
  not called. It is a loop callback, so every `wired_server_wt_*` send API
  may be called from it. The loop already polls with a bounded timeout
  (`SRVRUN_PTO_MS`, 25 ms) whenever a connection is live, so the callback
  fires at least that often while anyone is connected; when no connection
  exists it may not fire at all, which is harmless because the live track's
  position is derived from the clock, not from tick counts.
- `int wired_server_wt_stream_inflight(wired_wt_session* s, u64 stream_id)`:
  1 while a send slot still holds `stream_id` (its bytes not yet fully
  acknowledged, or the stream still open for appends), 0 once the slot was
  reaped or the id was never a server-sent stream on this session. This is
  the signal an app needs to know when a payload it handed over as a VIEW
  (a payload above the slot's staging capacity) can be reused.

Both are forwarded unchanged by the other drivers (workers/threads/xdp) the
way the existing `wt_on_*` callbacks are.

### 3. Hub live track (`src/app/moqt/run/moqtrun.[ch]`)

New state on `wired_moqt_hub`:

```c
typedef struct {
  wired_moqtrun_track track;      /* name, own_alias, subs[] (peers subscribed) */
  const wired_span*   frags;      /* caller-owned fragment views */
  usz                 n_frags;
  u64                 t0_ms;
  u64                 group_ms;
  u64                 sent_group[WIRED_MOQTRUN_MAX_SUBS]; /* per sub slot: last Group sent */
  int                 sent_any[WIRED_MOQTRUN_MAX_SUBS];   /* 0 until the first Group */
} wired_moqtrun_live;
```

API:

```c
/* Publish a hub-owned live track: fragment i is sent as Group g's only
 * Object whenever g mod n_frags == i, Groups advancing every group_ms
 * from now_ms. frags must outlive the hub. Returns 0 on n_frags == 0 or
 * group_ms == 0. */
int wired_moqt_publish_live(wired_moqt_hub* hub, wired_span name,
    u64 track_alias, const wired_span* frags, usz n_frags,
    u64 group_ms, u64 now_ms);

/* Clock tick (wired_srvrun_opt.on_step): computes the current Group from
 * now_ms and sends it to every live subscriber that has not received it. */
void wired_moqt_tick(wired_moqt_hub* hub, u64 now_ms);
```

Behavior:

- `SUBSCRIBE movie` (name match on the live track, checked after the blob
  track and before peer tracks): record the peer in `subs[]`, queue
  SUBSCRIBE_OK with the live alias, and send the current Group to it at
  once (`sent_group` = current). No free sub slot: REQUEST_ERROR
  INTERNAL_ERROR. A repeat SUBSCRIBE from a peer already subscribed:
  SUBSCRIBE_OK again, nothing sent.
- `wired_moqt_tick(now)`: `g = (now - t0) / group_ms`. For each active sub
  with `sent_group < g` (or `!sent_any`): build the Group stream for
  fragment `g mod n_frags` and call `io.send_uni`. On acceptance
  `sent_group = g`. On refusal (the session has no free staging or send
  slot) nothing is recorded: the send is retried on the next tick while
  the clock is still in Group g, and abandoned once the clock moves on
  (`stat_live_drop++` per Group skipped for a subscriber). A subscriber
  therefore never receives a Group out of order and never receives the
  same Group twice.
- Session close: the peer's live subscription is dropped like its other
  subscriptions (a reconnect starts from the then-current Group).
- Framing per send: the hub builds SUBGROUP_HEADER + Object ID Delta +
  Payload Length into a small stack buffer and hands `io.send_uni` a
  payload that is the framing followed by the fragment. Because the
  io table takes one contiguous span, the hub needs `moqdata`'s help to
  frame directly in front of the fragment bytes without copying 400 KB
  per subscriber: the example's io adapter already copies the payload
  into per-session staging (see 4), so the hub passes a two-part payload
  through a new io entry:

  ```c
  /* wired_server_wt_open_uni-shaped, for a payload whose first part is a
   * short framing prefix and whose second part is a large body the hub
   * does not own a contiguous copy of. The adapter concatenates them. */
  i64 (*send_uni2)(wired_wt_session* s, wired_span head, wired_span body);
  ```

  The existing `send_uni` stays for the chat/blob paths. The test stub
  records `head||body`.

Counters added to the hub: `stat_live_sent`, `stat_live_drop`, logged at
shutdown with the relay stats.

### 4. Example server (`examples/moqt_chat/wired_server.c`)

- `--movie PATH` now expects the fMP4. Boot: `wired_fio_read` into an 8 MiB
  static buffer, `mp4frag_scan`, then `wired_moqt_publish_blob("movie/init",
  9, init, ...)` and `wired_moqt_publish_live("movie", 8, frags, n, 2000,
  clock_mono_ms())`. Scan failure is fatal with a message naming the flag.
  Log one line: fragment count, init bytes, group cadence.
- `opt.run.on_step` = a function calling `wired_moqt_tick(&g_hub, now_ms)`.
- Per-session staging becomes a ring: `LIVE_RING = 3` slots of
  `LIVE_FRAG_MAX = 1 MiB` (rationale: the largest fragment is 405 KB; a
  2-second fragment at 4 Mbps is 1 MB) per session, `BIG_SLOTS` sessions as
  today. `send_uni2` claims the first slot whose recorded stream is no
  longer `wired_server_wt_stream_inflight`, writes signal prefix + head +
  body, opens the stream, records the stream id in the slot. No free slot,
  or head+body larger than the slot: return -1 (the hub counts a drop).
  Session close frees all of the session's slots.
- The blob path's 8 MB big slot pool is removed: `movie/init` is 1.2 KB and
  rides the existing 2 KB stack path. `send_uni` keeps refusing payloads
  above the stack staging (no caller sends one any more).

## Browser client (`examples/moqt_chat/frontend`)

`src/lib/moqtLiveClient.ts`:

- Constants `MOVIE_TRACK_NAME = "movie"`, `MOVIE_INIT_TRACK_NAME =
  "movie/init"`, `MOVIE_TRACK_ALIAS = 8n`, `MOVIE_INIT_TRACK_ALIAS = 9n`,
  `MOVIE_MIME = 'video/mp4; codecs="avc1.640015, mp4a.40.2"'`.
  (`avc1.640015` is written after reading the generated file's `avcC`:
  High profile 0x64, constraints 0x00, level 0x15 for 480p24 — verified
  during implementation, not assumed.)
- `startLive(chat, video)`: creates a `MediaSource`, attaches it to the
  `<video>`, and on `sourceopen` adds one `SourceBuffer(MOVIE_MIME)` with
  `mode = "sequence"` (timestamps restart when the asset loops; sequence
  mode appends by arrival order and ignores them). SUBSCRIBEs `movie/init`
  first; when its bytes arrive (through the existing blob read path), they
  are appended, and only then is `movie` SUBSCRIBEd.
- Incoming uni streams with alias 8: read to EOF, decode exactly one Object
  (`decodeBlobObjects` already does this shape), push the payload onto an
  append queue. The queue appends one buffer at a time, waiting for
  `updateend` between appends (SourceBuffer rejects concurrent appends).
  The queue is a pure, testable unit (`AppendQueue`) fed by a fake
  SourceBuffer in tests.
- Buffer hygiene: after each append, if more than 60 seconds are buffered
  behind `currentTime`, `remove(0, currentTime - 30)` (queued like an
  append). Keeps memory bounded across a long-running loop.
- Playback: `<video data-testid="live" autoplay muted playsInline controls>`.
  Muted autoplay is allowed without a gesture; the user can unmute.
- Errors: a decode failure on one stream drops that Group; a `SourceBuffer`
  error surfaces as a store error string, nothing crashes chat/voice.

`useMoqtChat.ts`: replaces the movie Blob wiring with `startLive` after
chat connects; alias 9 routes to the blob reader (init), alias 8 to the live
reader; `leave()` tears the MediaSource down. The store's `movieUrl`
becomes `liveError: string | null`; `page.tsx` renders the `<video>` above
the message list once connected.

## Verification

Properties the live sender must hold (each becomes at least one test):

- A subscriber never receives the same Group twice.
- A subscriber receives Groups in strictly increasing order; a Group the
  clock has already left is never sent late.
- A staging slot whose stream is still in flight is never overwritten; a
  slot is reused only after the SDK reports its stream done.
- A refused send never loses state: it is retried while the clock stays in
  that Group and counted as a drop once the clock moves on.
- If slots keep being released, every subscriber eventually receives a
  Group newer than any given one (no subscriber is starved by another).
- Session close releases the peer's subscription and its slots; a reconnect
  starts at the clock's current Group.

These are checked as a state model before the C code is written (the
interplay of ticks, subscribes, closes and slot releases is the part most
likely to hide an ordering bug), and the test list below carries one test
per property. Everything else is plain test-first development.

Test list (C):

- mp4frag: synthetic fMP4 (ftyp, moov, 2 x moof+mdat) scans to init + 2
  fragments with exact spans; a `free` box between fragments is skipped;
  moof without mdat, truncated box, largesize box, zero-size box, and more
  than the cap all return 0; the real asset scans to 16 fragments and a
  1,260-byte init (pinned by size, not by bytes).
- srvrun: `on_step` fires once per step with a non-decreasing clock; a
  session's stream is `inflight` right after `wired_server_wt_open_uni` and
  no longer inflight after the loopback peer has acknowledged it.
- moqtrun live: publish rejects n_frags 0 / group_ms 0; SUBSCRIBE replies
  SUBSCRIBE_OK alias 8 and sends the current Group at once with the right
  header (alias 8, Group = clock Group) and the fragment as Object 0;
  tick within the same Group sends nothing more; tick into the next Group
  sends the next fragment; fragments wrap at n_frags; a refused send is
  retried on the next tick of the same Group and abandoned (counted) once
  the Group advances; two subscribers are served independently (one
  refused, the other not); session close stops sends and a reconnect starts
  at the current Group; blob track `movie/init` and live track `movie`
  coexist and route by name; `send_uni2`'s head||body equals a
  `moqdata_msg_build` of the same fragment.
- example (through the real-browser e2e): see below.

Test list (TypeScript, vitest):

- AppendQueue serializes appends across `updateend`, preserves order, and
  queues `remove` like an append; init is appended before any fragment;
  a fragment arriving before init waits; decode failure drops one Group
  only; MIME string matches the asset's `avcC` (test reads the committed
  file's `avcC` bytes and derives the codec string).

Real-browser check (`just e2e-live`, `e2e/run-live-check.mjs`): starts the
server with `--movie assets/movie-live.mp4`, joins user1, waits until
`video.currentTime` advances past 4 s with `readyState >= 3`; joins user2
5 s later and requires its first received Group ID (exposed on the video
element as `data-first-group`) to exceed user1's; both keep advancing; the
server's shutdown log shows `live_sent > 0`.

## Out of scope

Multiple bitrates or a catalog track, FETCH / rewind, Largest Location in
SUBSCRIBE_OK, per-frame Objects (one fragment per Group is the unit),
publisher-initiated PUBLISH announcements (subscribe-by-fixed-name stays,
as for every other track in this sample), separate audio/video tracks,
transcoding at runtime.

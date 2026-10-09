# MOQT chat sample

A chat + voice call room over Media over QUIC Transport
(draft-ietf-moq-transport-22, with a draft-19 fallback; see
[`moqt_interop`](../moqt_interop/) for the multi-draft relay): a libc-free
WebTransport server
(`wired_server.c`) relays each participant's chat messages and Opus voice
frames to every other connected participant, using the `app/moqt/run` hub
(`src/app/moqt/run/moqtrun.h`) wired onto real UDP.

## Draft versions: 22 first, 19 as the fallback

The server offers the hub's full WebTransport subprotocol list
(`wired_moqt_wt_protocols`: `moqt-22 moqt-19 moqt-18`) via
`opt.run.wt_protocols`. The browser client offers `protocols: ["moqt-22"]`
to `new WebTransport(...)`, and which draft the session runs depends on
whether the browser honours it:

- **Draft-22** (`wt.protocol === "moqt-22"`): the server opens a
  unidirectional control stream that starts with SETUP (stream type
  0x2F00, draft-22 9.1; session initialization 6.3) and later carries
  GOAWAY (9.2); the client opens its own unidirectional control stream and
  sends its SETUP. Requests stay one per client-opened bidirectional
  stream (6.4.2). Draft-22 removed the Joining FETCH, so history is a
  SUBSCRIBE carrying FILL_PARAMETERS (0x23) whose inner LOCATION_FILTER is
  RelativeStart N, with N = the old joining start + 1 (3.4 Fill Semantics,
  3.5 Joining an Ongoing Track). The fill arrives on a server
  unidirectional stream whose FETCH_HEADER (11.4.1) names the SUBSCRIBE's
  Request ID. The live filter that was "Largest Object" is LOCATION_FILTER
  NextObject (0x05, 9.20.9).
- **Draft-19 fallback** (no application-protocol negotiation): exactly the
  previous behavior. The hub's single bidirectional control stream carries
  SETUP (draft-19 10.3) and GOAWAY (10.4), and history is a Relative
  Joining FETCH (10.12.2).

Chromium exposes `WebTransportOptions.protocols` / `wt.protocol` only with
`--enable-experimental-web-platform-features` (as of Chromium 141). Without
that flag `protocols` is ignored and the session silently takes the
draft-19 path. Section numbers below cite draft-22, followed by the
draft-19 number where the fallback differs ("draft-22 X; draft-19 Y").

## What this demonstrates

Unlike a plain WebTransport DATAGRAM-broadcast chat (raw QUIC DATAGRAMs,
message framing left entirely to the frontend — the guide's browser chapter
builds one), this sample speaks MOQT on the wire. Each participant (one of the fixed ids `user1`..`user4`:
an id's index is its Track Alias) PUBLISHes up to three tracks under the
namespace `wired/moqt_chat` — `<id>` for chat, `<id>/audio` for voice and
`<id>/screen` for a screen share — plus a fourth, `<id>/screen-lo`, when
the hub offers track switching (see
[Track switching](#track-switching-screen-share-hilo-variants)). There is
a single fixed room.

- **Requests on their own streams** (draft-22 6.4.2; draft-19 3.3): every PUBLISH, SUBSCRIBE,
  FETCH, PUBLISH_NAMESPACE and SUBSCRIBE_NAMESPACE opens its own
  bidirectional stream with an even Request ID, and its answer comes back
  on that stream. Cancelling a request resets its stream. The control
  stream carries SETUP and, when the hub is shutting down, GOAWAY: the
  server's unidirectional control stream on draft-22, the hub's single
  bidirectional control stream on the draft-19 fallback.
- **Namespace discovery** (draft-22 4.1-4.2; draft-19 6.1-6.2): once its tracks are PUBLISHed, a
  client announces `wired/moqt_chat/<id>` and watches the `wired/moqt_chat`
  prefix. NAMESPACE for a peer puts it on the roster and subscribes its chat
  and audio; NAMESPACE_DONE takes it off and cancels those subscriptions. A
  screen share additionally announces `wired/moqt_chat/<id>/screen` while it
  runs. Nothing is polled.
- **History and late join** (draft-22 3.4-3.5; draft-19 10.12.2): a peer's
  chat track is subscribed from the Next Object (draft-19: Largest Object)
  and the 64 Groups before it are filled in, so a joiner sees recent
  messages: on draft-22 by FILL_PARAMETERS on the SUBSCRIBE, on the
  draft-19 fallback by a Relative Joining FETCH. Every screen-share
  keyframe starts a new Group, and a late viewer's fill (RelativeStart 1;
  draft-19: Joining Start 0) hands it the current Group from its keyframe,
  so the first frame decodes at once.
- **Objects**: a chat message's text is one Object in a Group of its own; an
  attachment is a Group of its own whose Objects are 15 KiB chunks (the hub
  holds at most 16384 bytes of one Object, `WIRED_MOQTRUN_RELAY_FRAG_MAX`).
  One Group per attachment is deliberate: the hub applies a subscription's
  Location Filter only on reliable late replay, so an attachment whose
  chunks shared a Group with later messages could reach a joiner torn --
  its own Group is either replayed whole or not at all;
  voice is one OBJECT_DATAGRAM per Opus frame (a stream when the frame is
  too large). The hub relays SUBGROUP bytes verbatim to every subscriber
  (`moqtrun.c`'s `moqtrun_relay_object`); chat tracks relay reliably, voice
  and screen drop rather than queue.

The wire codecs (varint/KVP/control messages/data messages) are implemented
independently in C (`src/app/moqt/vi`/`kvp`/`ctl`/`data`) and TypeScript
(`frontend/src/lib/moqtWire.ts`), both pinned against the same golden vectors
(`testvectors/moqt_golden.json`) so the two implementations are checked
against a shared, audited reference rather than only against each other.

## Track switching (screen share hi/lo variants)

**Experimental, draft-22 only.** This uses the hub's moqtail-compatible
SWITCH_FROM (0x24) / SSTS (SWITCHING_SET_ASSIGNMENT 0x41, Setup Option
SSTS_ALGORITHMS 0x09) extension. None of these code points is in
draft-22. See
[MoQT track switching](../../docs/features/moqt-track-switching.md) for
the wire format and the hub's rules, and
[Known Limitations](../../docs/features/known-limitations.md#moqt-track-switching-experimental)
for the gaps.

- **Two variants, shared Group numbers.** A sharer publishes the capture as
  `<id>/screen` (hi) and also as `<id>/screen-lo` (lo: at most 640 px wide,
  350 kbps, `screenSharePipeline.ts`). Both are cut from the same captured
  frames with one keyframe decision, so Group g of hi and Group g of lo
  start on the same frame. Track Aliases: hi is 10..13 and lo is 14..17
  (participant index + 10 / + 14, `moqtScreenClient.ts`).
- **Auto (the default).** A watcher subscribes to both variants as one
  switching set (Set ID = the sharer's participant index, thresholds hi
  2000 kbps / lo 400 kbps, Weight 1, Activate 2). The hub then forwards one
  of them per Group, chosen by the negotiated algorithm. The client prefers
  backpressure (0xff01) and falls back to default (0). If neither is
  negotiated, Auto subscribes to hi alone. Both variants feed
  the participant's one decoder. A Group gate drops the other variant's
  copy of a Group and a switched-away variant's tail.
- **High / Low.** The per-tile selector subscribes to one variant only.
  Moving between High and Low is one SUBSCRIBE carrying SWITCH_FROM
  {Soft, Publish Done} of the current subscription. The hub ends the old
  one at the Group boundary with PUBLISH_DONE 0x3, and the tile changes
  only once that SUBSCRIBE is accepted. Moving to or from Auto cancels and
  re-subscribes.
- **HI / LO badge.** Each remote screen tile shows which variant it is
  currently decoding, so a switch can be observed.
- **What the server must enable.** The hub advertises nothing until the
  server turns the extension on: SWITCH_FROM (`wired_moqt_hub.switch_track
  = 1`) and an SSTS algorithm list (`ssts_algs` / `ssts_alg_n`, plus
  `ssts_cap_kbps` for the default algorithm's budget), all set after
  `wired_moqt_init`. The client enables variants only when the hub's
  draft-22 SETUP carries SSTS_ALGORITHMS. `wired_server.c` turns both on
  with `switch_track = 1` and `ssts_algs = {0xff01 (backpressure), 0
  (default)}`, leaving `ssts_cap_kbps` at 0 (no cap).
- **One more track per peer.** `screen-lo` is a fourth PUBLISH per
  participant, which is why `WIRED_MOQTRUN_MAX_TRACKS_PER_PEER` went from 3
  to 4. If the hub refuses the lo PUBLISH, the sharer does not run the lo
  encoder.
- **Draft-19 fallback unchanged.** On draft-19, or against a hub without
  the extension, the client behaves as before: it publishes and subscribes
  `<id>/screen` (hi) only. There is no switching set and no Group gate, and
  the quality selector and HI/LO badge are not shown.

## Build and run (server)

The server runs in a `scratch` container: the binary is fully static
(`-ffreestanding -nostdlib -static`) and, by default, touches no filesystem
at runtime (its self-signed cert is generated in memory each boot), so the
image holds nothing besides `wired_server`. Mount a PEM pair and point
`WIRED_CERT`/`WIRED_KEY` at it to serve a real certificate instead
(Configuration below).

```sh
cd examples/moqt_chat
just up       # builds, then runs in the foreground, Ctrl-C stops it
just up-bg    # same, but detached; `docker compose logs -f` to follow it, `just down` to tear it down
```

The container runs with `network_mode: host` (see `docker-compose.yml`), so
`wired_server` listens on the host's own `4433/udp` directly rather than
through a NAT'd port mapping — a bridge-network `-p 4433:4433/udp` setup was
confirmed by hand to never complete the QUIC handshake (the client sits at
"Connecting..." forever), while host networking connects immediately.

This hub keeps its peer table, request streams and object cache in one
process's memory, so it is single-process only: do not pass
`--workers`/`--cores`/`--ifindex` (each worker would run its own room).

### Configuration

| Flag / environment | Default | Effect |
|---|---|---|
| `--port N` | 4433 | UDP port |
| `--cc cubic\|bbr` | `cubic` | congestion controller for new connections |
| `--cert PATH` / `WIRED_CERT` | unset (self-signed, in memory) | fullchain PEM (leaf first) to serve |
| `--key PATH` / `WIRED_KEY` | unset | its P-256 private key (PEM); required with a cert |
| `WIRED_ALLOWED_ORIGINS` | unset (every Origin accepted) | comma-separated exact Origins, e.g. `https://chat.example,https://localhost:8443`; a WebTransport CONNECT from any other Origin is answered 403 (draft-ietf-webtrans-http3-15 3.1) |
| `--goaway-uri URI` / `WIRED_GOAWAY_URI` | unset (reconnect to the same URI) | New Session URI sent in GOAWAY on shutdown (at most 512 bytes) |

- **Certificate reload**: with `--cert`/`--key` set, `kill -HUP <pid>`
  re-reads both files; connections opened afterwards use the new
  certificate, open ones are not disturbed. A pair that fails to load leaves
  the old one in place.
- **Object cache**: the hub keeps the last 1 MiB of Objects (all tracks in
  one arena, the oldest whole Group evicted first) to answer FETCH. A busy
  screen share therefore pushes chat history out of it quickly, and one
  Group larger than the arena (a single attachment over ~1 MiB) is not
  cached at all, so a joiner's history skips it.
- **Namespaces**: only namespaces under `wired/moqt_chat` may be announced
  or watched; anything else is refused UNAUTHORIZED.
- **Request-stream budget**: the hub tracks at most 24 open request streams
  per session and 96 hub-wide (`WIRED_MOQTRUN_MAX_REQS`); past that a new
  request stream is reset EXCESSIVE_LOAD. A full 4-user room keeps up to 15
  live per session (3 PUBLISH + 2 PUBLISH_NAMESPACE + SUBSCRIBE_NAMESPACE +
  9 SUBSCRIBEs), which is why the client sends history FETCHes one at a
  time on draft-19 (a draft-22 fill rides its SUBSCRIBE's request and needs
  no slot of its own) and the id pool stays at four.
  With track switching on (draft-22 and a hub that advertises 0x09), the
  worst case grows: 4 PUBLISH + 2 PUBLISH_NAMESPACE + SUBSCRIBE_NAMESPACE +
  12 SUBSCRIBEs (`screen` and `screen-lo` for each of 3 sharing peers in
  Auto) = 19 per session, 76 hub-wide, so the hub's pool was raised to 96
  (`WIRED_MOQTRUN_MAX_REQS`), a per-session budget of 24.
- **Fill capacity (draft-22)**: fills share one hub-wide table of 8 serving
  slots plus 8 waiting (`WIRED_MOQTRUN_MAX_FETCHES`, together with
  draft-19 FETCHes). When both are full the hub refuses the whole
  history SUBSCRIBE with REQUEST_ERROR INTERNAL_ERROR (draft-22 3.4.1: an
  accepted fill must get a fill fetch stream, so the hub decides before
  answering); the client then retries
  that SUBSCRIBE once without FILL_PARAMETERS, so the peer is followed live
  without history -- the same result as a refused Joining FETCH on
  draft-19.

### Graceful restart

On SIGTERM (`docker compose stop`, `kill <pid>`) the hub stops accepting
connections and sends every MOQT session GOAWAY (draft-22 6.6.1 / 9.2; draft-19 3.6 / 10.4) with a
2 s timeout and the `WIRED_GOAWAY_URI`; it exits after the SDK's ~5 s drain.
The browser reconnects as soon as the GOAWAY (or a WebTransport drain)
arrives — to the new URI when one was given — and the fresh session
publishes, announces and subscribes everything again. While the old hub
drains it refuses new connections, so the reconnect retries on the
auto-rejoin back-off (1 s, 2 s, 4 s, ...) until the restarted hub answers.
A restart on the same UTC day keeps the self-signed fingerprint, so the
pinned hash still matches.

NewReno is not selectable through `--cc` (any value other than `cubic` or
`bbr` exits with a usage error).

On startup it logs the self-signed certificate's SHA-256 fingerprint:

```
cert sha-256 fingerprint: b4:6d:57:7b:de:f6:70:d6:f1:f9:e9:91:c3:a3:6a:db:15:e8:7d:39:34:24:a4:54:89:ed:de:43:22:39:70:88
```

This value stays the same across restarts on the same UTC day (the
certificate's validity window is anchored to the start of the day, not the
exact startup time, so the frontend's auto-rejoin can keep using a pinned
hash) but changes after UTC midnight, so copy it from the **current** run if
it has crossed a day boundary.

## Run the frontend

The frontend is a Next.js + React app with its own stylesheet, modelled on
the 1976 NASA Graphics Standards Manual
(`output: "export"`, so it ships as static files — no Node server needed to
serve it).

```sh
just serve-frontend   # builds frontend/ and serves it over TLS at :8443
```

A non-`localhost` HTTP page is not a secure context, so the frontend is
served over TLS; a self-signed `cert.pem`/`key.pem` pair is generated
automatically on first run. Open `https://<host>:8443/`, paste the server's
cert fingerprint, pick a participant id, and connect. Voice starts
automatically once connected (mutable via the mic toggle); grant the
browser's microphone permission prompt to send audio. Open it again with a
different participant id (or a private window) to chat with yourself across
two tabs.

For local development with hot reload instead: `just dev-frontend` (plain
HTTP at `:3000`, works for `localhost` since that origin is always a secure
context regardless of scheme).

### Hosted on GitHub Pages

This repo's [Docs workflow](../../.github/workflows/docs.yml) also publishes
this frontend as a static demo at `https://<user>.github.io/wired/moqt_chat/`,
alongside the SDK's Doxygen API reference at the site's root. GitHub Pages
only serves static files, so it hosts the frontend's assets — it cannot run
`wired_server` itself (that needs a real UDP/QUIC listener). Run the server
somewhere reachable (a VM, a home machine with a forwarded port, ...), then
point the hosted page's "Server URL" field at it and paste its logged cert
fingerprint, same as running the frontend locally. The self-signed
cert/fingerprint pair is still per-run: this hosted page is a convenient
client, not a zero-setup public demo.

## Multi-client e2e test

```sh
just e2e-setup                                        # once: installs deps + Chrome for Testing
just e2e-load --clients=4 --messages=10 --max-loss-rate=0
```

Every e2e entry point binds and dials `WIRED_E2E_PORT` (default 4433) and
stops only the hub it started — set it to a free port on a host that
already runs a hub, e.g. `WIRED_E2E_PORT=14833 just e2e-stability
s21-sigterm-goaway`. Besides the load test, `just e2e-stability <id>` runs
one scenario from `e2e/scenarios/`, among them `s16-history-join`,
`s17-video-join-keyframe`, `s18-discovery`, `s19-origin-403`,
`s20-attachment-1mb` and `s21-sigterm-goaway` for the behavior above.

Starts the server and frontend, drives up to `MAX_CLIENTS=4` headless-Chrome
participants (the frontend's fixed candidate id list), has each send several
chat messages, and grades the run for message loss and latency. This grades
chat only — sample-accurate audio content isn't checked here; voice call
verification is manual (see above). See `e2e/run.sh` and
`e2e/lib/loadTest.mjs` for the harness. `?ns=0` on the page URL starts with
RNNoise off; the e2e harness uses it so its transport gates measure the
network path, not the noise-suppression worklet's own CPU cost.

### Exercising draft-22 in a real browser

The e2e scenarios drive the UI only and do not choose a draft: a stock
Chrome for Testing takes the draft-19 fallback. To exercise draft-22, run
the browser with `--enable-experimental-web-platform-features` (for a
manual check, start Chrome/Chromium with that flag against
`just serve-frontend`; the session then negotiates `moqt-22`, visible as
`wt.protocol` in the browser and as `MoqtChatClient.draft === 22`, which
the page does not display: inspect the client in devtools). A browser that
offers `protocols` but has no `wt.protocol` attribute is detected by the
hub's first control stream (a unidirectional SETUP means draft-22). The harness
launches Chrome from fixed `args` lists in its `puppeteer.launch` calls
(`e2e/run-scenario.mjs`, `e2e/lib/stabilityClient.mjs`, ...) and has no
option for extra Chrome arguments; adding that flag to those lists is
needed to run the scenarios on draft-22.

## Layout

- `wired_server.c` — the MOQT hub server: wires WebTransport session/stream
  callbacks to `src/app/moqt/run`'s hub and adapts `wired_server_wt_*` into
  its `wired_moqt_io` send table (prefixing the WebTransport stream signal,
  draft-ietf-webtrans-http3-15 SS4.2), plus the Origin allow-list, the
  certificate paths, the object cache and GOAWAY on shutdown.
- `Dockerfile` / `docker-compose.yml` — the `scratch` image `just up`/
  `up-bg` build and run (see "Build and run (server)" above).
- `frontend/` — the Next.js + React browser client:
  `src/lib/moqtWire.ts`/`moqtClient.ts` (wire codec; session, request
  streams, discovery, history fill / FETCH, GOAWAY; draft-22 and draft-19), `moqtScreenWire.ts`/`moqtScreenClient.ts`
  (screen share, its hi/lo variants and track switching), `moqtVoiceWire.ts`/`moqtVoiceClient.ts` (voice Object
  framing and the audio track's publish/subscribe), `src/lib/*Pipeline.ts` +
  `jitterBuffer.ts`/`playbackSink.ts`/`audioContextGate.ts` (mic capture ->
  Opus encode -> MOQT Object, and the receive-side jitter/decode/playback
  path), `src/app/page.tsx` +
  `src/stores/moqtChatStore.ts` + `src/hooks/useMoqtChat.ts` (UI).
- `e2e/` — the multi-client load-test harness.
- `testvectors/moqt_golden.json` — the shared C/TypeScript golden vectors.

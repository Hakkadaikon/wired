# MOQT chat sample

A chat + voice call room over Media over QUIC Transport
(draft-ietf-moq-transport-19): a libc-free WebTransport server
(`wired_server.c`) relays each participant's chat messages and Opus voice
frames to every other connected participant, using the `app/moqt/run` hub
(`src/app/moqt/run/moqtrun.h`) wired onto real UDP.

## What this demonstrates

Unlike `examples/webtransport_chat` (which broadcasts raw QUIC DATAGRAMs and
leaves the message framing entirely to the frontend), this sample speaks
MOQT on the wire. Each participant (one of the fixed ids `user1`..`user4`:
an id's index is its Track Alias) PUBLISHes up to three tracks under the
namespace `wired/moqt_chat` — `<id>` for chat, `<id>/audio` for voice and
`<id>/screen` for a screen share. There is a single fixed room.

- **Requests on their own streams** (draft 3.3): every PUBLISH, SUBSCRIBE,
  FETCH, PUBLISH_NAMESPACE and SUBSCRIBE_NAMESPACE opens its own
  bidirectional stream with an even Request ID, and its answer comes back
  on that stream. Cancelling a request resets its stream. The hub's own
  control stream carries SETUP and, when the hub is shutting down, GOAWAY.
- **Namespace discovery** (draft 6.1-6.2): once its tracks are PUBLISHed, a
  client announces `wired/moqt_chat/<id>` and watches the `wired/moqt_chat`
  prefix. NAMESPACE for a peer puts it on the roster and subscribes its chat
  and audio; NAMESPACE_DONE takes it off and cancels those subscriptions. A
  screen share additionally announces `wired/moqt_chat/<id>/screen` while it
  runs. Nothing is polled.
- **History and late join** (draft 10.12.2): a peer's chat track is
  subscribed from the Largest Object together with a Relative Joining FETCH
  of the 64 Groups before it, so a joiner sees recent messages. Every
  screen-share keyframe starts a new Group, and a late viewer's Joining
  FETCH (Joining Start 0) hands it the current Group from its keyframe, so
  the first frame decodes at once.
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
- **Request-stream budget**: the hub tracks at most 16 open request streams
  per session and 64 hub-wide (`WIRED_MOQTRUN_MAX_REQS`); past that a new
  request stream is reset EXCESSIVE_LOAD. A full 4-user room keeps up to 15
  live per session (3 PUBLISH + 2 PUBLISH_NAMESPACE + SUBSCRIBE_NAMESPACE +
  9 SUBSCRIBEs), which is why the client sends history FETCHes one at a
  time and the id pool stays at four.

### Graceful restart

On SIGTERM (`docker compose stop`, `kill <pid>`) the hub stops accepting
connections and sends every MOQT session GOAWAY (draft 3.6 / 10.4) with a
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
  streams, discovery, FETCH, GOAWAY), `moqtScreenWire.ts`/`moqtScreenClient.ts`
  (screen share), `moqtVoiceWire.ts`/`moqtVoiceClient.ts` (voice Object
  framing and the audio track's publish/subscribe), `src/lib/*Pipeline.ts` +
  `jitterBuffer.ts`/`playbackSink.ts`/`audioContextGate.ts` (mic capture ->
  Opus encode -> MOQT Object, and the receive-side jitter/decode/playback
  path, ported from `examples/webtransport_chat`), `src/app/page.tsx` +
  `src/stores/moqtChatStore.ts` + `src/hooks/useMoqtChat.ts` (UI).
- `e2e/` — the multi-client load-test harness (ported from
  `examples/webtransport_chat/e2e`).
- `testvectors/moqt_golden.json` — the shared C/TypeScript golden vectors.

# MOQT chat sample

A chat + voice call room over Media over QUIC Transport
(draft-ietf-moq-transport-19): a libc-free WebTransport server
(`wired_server.c`) relays each participant's chat messages and Opus voice
frames to every other connected participant, using the `app/moqt/run` hub
(`src/app/moqt/run/moqtrun.h`) wired onto real UDP. The server also
publishes a live movie stream of its own: the fragmented MP4
`assets/movie-live.mp4`, paced by the wall clock, which every participant
receives and plays on joining — a late joiner picks the stream up at its
current live position, not the file's start.

## What this demonstrates

Unlike `examples/webtransport_chat` (which broadcasts raw QUIC DATAGRAMs and
leaves the message framing entirely to the frontend), this sample speaks an
actual MOQT subset on the wire: each participant PUBLISHes two
fixed-namespace tracks — `<id>` for chat, `<id>/audio` for voice — and
SUBSCRIBEs to the other candidates' matching tracks in a small fixed pool
(`user1`..`user4` — this subset has no namespace discovery, see
`moqtClient.ts`'s own doc). There is a single fixed room; unlike
`webtransport_chat`'s client-side room tag, MOQT's track addressing makes a
separate room concept unnecessary here.

A chat message is sent as one MOQT Object (SUBGROUP_HEADER + Object,
`frontend/src/lib/moqtWire.ts`) on its own unidirectional stream. Each Opus
frame is sent the same way (`frontend/src/lib/moqtVoiceWire.ts`): one
complete SUBGROUP_HEADER + Object per fresh uni stream, matching the hub's
own per-call relay unit (`moqtrun.c`'s `moqtrun_relay_to_one` forwards each
relayed chunk as its own one-shot stream) rather than a single long-lived
stream. The hub relays the SUBGROUP bytes verbatim to every Established
subscriber of that track (`moqtrun.c`'s `moqtrun_relay_object`); a single
peer can PUBLISH both tracks at once (`moqtrun.h`'s per-peer track array).

The server is a publisher too: started with `--movie PATH`, it reads the
fragmented MP4 once at boot, splits it into the init segment (`ftyp`+`moov`)
and its `moof`+`mdat` fragments, and publishes two hub-owned tracks (after
the chat aliases 0..3 and audio aliases 4..7):

- `movie/init` (Track Alias 9): the init segment, as a static blob track
  (`wired_moqt_publish_blob`) — one stream, sent once per subscriber on
  SUBSCRIBE.
- `movie` (Track Alias 8): the live track. The hub derives the current
  Group from the wall clock (one Group per 2 seconds, counted from
  publish time); Group g carries fragment `g mod 15` as the Group's only
  Object, on its own unidirectional stream, sent when the clock enters
  the Group. The asset loops, but the Group IDs keep increasing.

A subscriber immediately receives the current Group (each fragment starts
with a keyframe, so playback begins at once) and then every later Group as
the clock enters it — which is why a late joiner starts at the live
position instead of the file's beginning. The frontend
(`frontend/src/lib/moqtLiveClient.ts`) SUBSCRIBEs `movie/init` first,
appends it to a `MediaSource` `SourceBuffer` (MSE, `mode = "sequence"` so
the looping asset's restarting timestamps don't matter), then SUBSCRIBEs
`movie` and appends each Group's fragment in arrival order into the
`<video>` element.

`assets/movie-live.mp4` is generated from `assets/movie.mp4` once with:

```sh
nix shell nixpkgs#ffmpeg-headless -c ffmpeg -i assets/movie.mp4 \
  -t 30 -af apad=whole_dur=30 \
  -c:v libx264 -preset medium -profile:v high -g 48 -keyint_min 48 \
  -sc_threshold 0 -b:v 1200k -c:a aac -b:a 128k \
  -movflags +frag_keyframe+empty_moov+default_base_moof \
  -f mp4 assets/movie-live.mp4
```

The wire codecs (varint/KVP/control messages/data messages) are implemented
independently in C (`src/app/moqt/vi`/`kvp`/`ctl`/`data`) and TypeScript
(`frontend/src/lib/moqtWire.ts`), both pinned against the same golden vectors
(`testvectors/moqt_golden.json`) so the two implementations are checked
against a shared, audited reference rather than only against each other.

## Build and run (server)

The server runs in a `scratch` container: the binary is fully static
(`-ffreestanding -nostdlib -static`) and touches no filesystem at runtime
except `movie-live.mp4`, which it reads once at boot (its self-signed cert
is generated in memory each boot, not read from disk), so the image holds
nothing besides `wired_server` and that file. The image's entrypoint
passes `--movie /movie.mp4`; running the binary by hand, pass
`--movie ../../assets/movie-live.mp4` (or omit the flag for a server
without the movie tracks -- clients then get `REQUEST_ERROR` for them and
simply show no video).

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

This hub keeps its peer table in one process's memory, so it is
single-process only: do not pass `--workers`/`--cores`/`--ifindex`.

`--cc cubic` (default) or `--cc bbr` selects the congestion controller for
new connections; NewReno is not selectable through this flag (any other
value exits with a usage error).

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

Starts the server and frontend, drives up to `MAX_CLIENTS=4` headless-Chrome
participants (the frontend's fixed candidate id list), has each send several
chat messages, and grades the run for message loss and latency. This grades
chat only — sample-accurate audio content isn't checked here; voice call
verification is manual (see above). See `e2e/run.sh` and
`e2e/lib/loadTest.mjs` for the harness.

```sh
just e2e-live
```

Checks the live movie track end to end against a real browser: two
participants join 5 seconds apart, each one's `<video>` must reach playable
state and keep advancing, the late joiner's first Group must be later than
the first participant's (live position, not the file's start), and the
server's shutdown stats must count live Group sends
(`e2e/run-live-check.mjs`).

## Layout

- `wired_server.c` — the MOQT hub server: wires WebTransport session/stream
  callbacks to `src/app/moqt/run`'s hub and adapts `wired_server_wt_*` into
  its `wired_moqt_io` send table (prefixing the WebTransport stream signal,
  draft-ietf-webtrans-http3-15 SS4.2).
- `Dockerfile` / `docker-compose.yml` — the `scratch` image `just up`/
  `up-bg` build and run (see "Build and run (server)" above).
- `frontend/` — the Next.js + React browser client:
  `src/lib/moqtWire.ts`/`moqtClient.ts` (chat wire codec, session/PUBLISH/
  SUBSCRIBE/relay), `moqtVoiceWire.ts`/`moqtVoiceClient.ts` (voice Object
  framing and the audio track's publish/subscribe), `moqtMovieClient.ts`
  (blob-track subscribe + Object reassembly, used for `movie/init`),
  `moqtLiveClient.ts` (the live `movie` track's subscribe + MSE append
  queue), `src/lib/*Pipeline.ts` +
  `jitterBuffer.ts`/`playbackSink.ts`/`audioContextGate.ts` (mic capture ->
  Opus encode -> MOQT Object, and the receive-side jitter/decode/playback
  path, ported from `examples/webtransport_chat`), `src/app/page.tsx` +
  `src/stores/moqtChatStore.ts` + `src/hooks/useMoqtChat.ts` (UI).
- `e2e/` — the multi-client load-test harness (ported from
  `examples/webtransport_chat/e2e`) and the live-movie check
  (`run-live-check.mjs`).
- `testvectors/moqt_golden.json` — the shared C/TypeScript golden vectors.

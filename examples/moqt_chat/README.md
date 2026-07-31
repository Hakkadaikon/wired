# MOQT chat sample

A chat + voice call room over Media over QUIC Transport
(draft-ietf-moq-transport-19): a libc-free WebTransport server
(`wired_server.c`) relays each participant's chat messages and Opus voice
frames to every other connected participant, using the `app/moqt/run` hub
(`src/app/moqt/run/moqtrun.h`) wired onto real UDP.

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

The wire codecs (varint/KVP/control messages/data messages) are implemented
independently in C (`src/app/moqt/vi`/`kvp`/`ctl`/`data`) and TypeScript
(`frontend/src/lib/moqtWire.ts`), both pinned against the same golden vectors
(`testvectors/moqt_golden.json`) so the two implementations are checked
against a shared, audited reference rather than only against each other.

## Build and run (server)

```sh
cd examples/moqt_chat
just run     # plain UDP socket, binds 0.0.0.0:4433, Ctrl-C to stop
```

This hub keeps its peer table in one process's memory, so it is
single-process only: do not pass `--workers`/`--cores`/`--ifindex`.

On startup it logs the self-signed certificate's SHA-256 fingerprint:

```
cert sha-256 fingerprint: b4:6d:57:7b:de:f6:70:d6:f1:f9:e9:91:c3:a3:6a:db:15:e8:7d:39:34:24:a4:54:89:ed:de:43:22:39:70:88
```

This value changes on every restart (the certificate's validity window is
anchored to the startup time), so always copy it from the **current** run.

## Run the frontend

The frontend is a Next.js + React app using the LiftKit design system
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

## Layout

- `wired_server.c` — the MOQT hub server: wires WebTransport session/stream
  callbacks to `src/app/moqt/run`'s hub and adapts `wired_server_wt_*` into
  its `wired_moqt_io` send table (prefixing the WebTransport stream signal,
  draft-ietf-webtrans-http3-15 SS4.2).
- `frontend/` — the Next.js + LiftKit browser client:
  `src/lib/moqtWire.ts`/`moqtClient.ts` (chat wire codec, session/PUBLISH/
  SUBSCRIBE/relay), `moqtVoiceWire.ts`/`moqtVoiceClient.ts` (voice Object
  framing and the audio track's publish/subscribe), `src/lib/*Pipeline.ts` +
  `jitterBuffer.ts`/`playbackSink.ts`/`audioContextGate.ts` (mic capture ->
  Opus encode -> MOQT Object, and the receive-side jitter/decode/playback
  path, ported from `examples/webtransport_chat`), `src/app/page.tsx` +
  `src/stores/moqtChatStore.ts` + `src/hooks/useMoqtChat.ts` (UI).
- `e2e/` — the multi-client load-test harness (ported from
  `examples/webtransport_chat/e2e`).
- `testvectors/moqt_golden.json` — the shared C/TypeScript golden vectors.

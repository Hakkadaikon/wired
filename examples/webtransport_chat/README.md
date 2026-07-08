# WebTransport chat sample

A minimal, real chat app over WebTransport: a libc-free HTTP/3 server
(`wired_server.c`) broadcasts every received QUIC DATAGRAM to every other
connected client, and a framework-free JavaScript frontend
(`public/`) sends/receives them from the browser.

## What this demonstrates

Unlike `examples/webtransport_echo` (which only exercises the WebTransport
building blocks at startup, with no live wire traffic), this sample is a real
end-to-end WebTransport session: Extended CONNECT establishes the session,
`wired_wt_on_datagram` receives each client's message, and the SDK's
`wired_server_broadcast_datagram` (`src/app/http3/server/srvrun/srvrun.h`)
fans it out to every other active session. The server never parses message
contents — it is a dumb relay; the chat protocol (author/text/timestamp,
JSON-over-DATAGRAM) lives entirely in the frontend's `application/chatSession.js`.

## Build and run (server)

```sh
cd examples/webtransport_chat
just run     # binds 0.0.0.0:4433, Ctrl-C to stop
```

On startup it logs the self-signed certificate's SHA-256 fingerprint:

```
cert sha-256 fingerprint: b4:6d:57:7b:de:f6:70:d6:f1:f9:e9:91:c3:a3:6a:db:15:e8:7d:39:34:24:a4:54:89:ed:de:43:22:39:70:88
```

This value is deterministic (fixed demo key material, same recipe as
`word_list`/`webtransport_echo`) — it will be the same every run unless you
edit `server_identity`'s seed bytes.

## Serve the frontend

The frontend is a separate static site — WebTransport does not require it to
be served by the same process, only from the same-origin browser tab that
opens the `WebTransport` connection to `https://localhost:4433/`. Any static
file server works; ES module `import` requires HTTP(S), not `file://`:

```sh
cd examples/webtransport_chat/public
python3 -m http.server 8000
```

## Connect from Chrome

Self-signed certificates fail normal CA validation, so WebTransport requires
opting in via `serverCertificateHashes` — this is what the frontend's
"証明書ハッシュ" field is for.

1. Copy the `cert sha-256 fingerprint: ...` value from the server's startup
   log (colons are fine, the frontend strips them).
2. Open `http://localhost:8000/` (the frontend, not the WebTransport server
   itself — no HTTPS needed for a plain static file server).
3. Paste the fingerprint into the "証明書ハッシュ" field, confirm the server
   URL (`https://localhost:4433/` by default), click "接続".
4. Enter a name and message, hit "送信". Open the page in a second tab (or
   another browser window) and confirm messages sent from one tab appear in
   the other.

### `serverCertificateHashes` constraints (read before debugging a connect failure)

The WebTransport spec requires a certificate pinned via
`serverCertificateHashes` to be an ECDSA cert with a validity period of at
most **14 days** (draft-ietf-webtrans-http3, referencing the WebRTC identity
provider security model). **This SDK's demo certificate does not meet that
constraint** — `quic_p256cert_build`'s fixed validity window is
2020-01-01–2030-01-01 (a 10-year span, chosen so a demo never needs
regenerating), which some browser versions may reject outright regardless of
a correct hash. If `serverCertificateHashes` is rejected for this reason in
your Chrome version, the practical workaround is launching Chrome with
`--ignore-certificate-errors-spki-list=<base64-spki-hash>` instead (a
different pinning mechanism with no validity-window constraint), or building
a real chart with `--cert`/`--key` external CA material (see `word_list`'s
README for that flow — this example does not yet expose the flags, see
Limitations below).

## Architecture

```
Server (C, libc-free)                Frontend (public/, plain JS, no framework)
─────────────────────                ────────────────────────────────────────
wired_server.c                       domain/          — ChatMessage, connection state
  wt_on_datagram_cb                                     (pure, no I/O, unit-tested)
    -> wired_server_broadcast_       application/    — ChatSession use case
       datagram (SDK, srvrun.h)                        (orchestrates domain +
                                                         infrastructure, unit-tested
                                                         against a mock client)
                                      infrastructure/ — WebTransportClient (thin
                                                         wrapper over the real
                                                         browser API), DomRenderer
                                                         (all DOM access lives here)
                                      app.js          — composition root (wiring only)
```

Each frontend layer's own file has more detail in a header comment. Tests
live in `public/tests/*.test.js`, driven by a self-written minimal assertion
runner (`public/tests/testRunner.js` — no framework, no bundler, no npm
dependency, per this repo's `examples/` convention of staying dependency-free).

## Testing

Server (SDK-level, from the repo root):
```sh
just test              # unity build, includes wired_server_broadcast_datagram's tests
just ninja              # freestanding compile, proves libc independence
lizard src --CCN 3 -w   # complexity gate
```

Frontend (from `public/tests/`):
```sh
node message.test.js
node connectionState.test.js
node chatSession.test.js
node webtransportClient.test.js
```
or open `public/tests/index.html` in a browser (served over HTTP, not
`file://` — see the comment in that file) to run all four with results
rendered on the page.

## Scope / limitations

- **DATAGRAM delivery is unreliable and unordered** (RFC 9221 1) — messages
  can be lost or arrive out of order. This is inherent to the transport this
  sample uses, not a bug. A production chat app would need a reliable
  delivery path; this SDK does not yet expose a server-to-client WebTransport
  *stream* send API (only DATAGRAM), so this sample is DATAGRAM-only by
  necessity, not by choice.
- **Broadcast is single-slot per connection, last-writer-wins**
  (`wired_server_broadcast_datagram`'s own doc, mirroring
  `srvrun_queue_datagram`) — if a second broadcast is queued before the first
  drains on some connection, the earlier one is silently overwritten on that
  connection specifically. Under normal chat message rates (far below one per
  network round trip) this is not observable in practice.
- No authentication, no persistence, no message history for a client that
  joins after a message was sent.
- The self-signed certificate's fixed 10-year validity window is
  incompatible with some browsers' `serverCertificateHashes` constraints —
  see the dedicated section above.
- `--cert`/`--key` (external CA certificate) are not wired into this
  example's CLI, unlike `word_list` — `--port` is the only flag. Add the same
  flow from `word_list/wired_server.c` if you need a certificate a browser
  accepts without the pinning workaround.

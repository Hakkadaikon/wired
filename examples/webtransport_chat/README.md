# WebTransport chat sample

A minimal, real chat app over WebTransport: a libc-free HTTP/3 server
(`wired_server.c`) broadcasts every received QUIC DATAGRAM to every
connected client, and a framework-free JavaScript frontend
(`public/`) sends/receives them from the browser.

## What this demonstrates

Unlike `examples/webtransport_echo` (which only exercises the WebTransport
building blocks at startup, with no live wire traffic), this sample is a real
end-to-end WebTransport session: Extended CONNECT establishes the session,
`wired_wt_on_datagram` receives each client's message, and the SDK's
`wired_server_broadcast_datagram` (`src/app/http3/server/srvrun/srvrun.h`)
fans it out to every active session — including the sender's own, which is
how the sender sees their message appear. The server never parses message
contents — it is a dumb relay; the chat protocol (author/text/timestamp,
JSON-over-DATAGRAM) lives entirely in the frontend's `application/chatSession.js`.

## Build and run (server)

```sh
cd examples/webtransport_chat
just run     # plain UDP socket, binds 0.0.0.0:4433, Ctrl-C to stop
```

Plain UDP is the default and works everywhere. When the browser will connect
to a bare IP instead of `localhost` (e.g. the server runs on a VPS), add
`--san-ipv4` so the self-signed certificate carries a matching IP SAN:

```sh
just build
./wired_server --san-ipv4 <a.b.c.d>
```

On startup it logs the self-signed certificate's SHA-256 fingerprint:

```
cert sha-256 fingerprint: b4:6d:57:7b:de:f6:70:d6:f1:f9:e9:91:c3:a3:6a:db:15:e8:7d:39:34:24:a4:54:89:ed:de:43:22:39:70:88
```

This value changes on every restart: the certificate's validity window is
anchored to the startup time (see the `serverCertificateHashes` constraints
below), so the DER — and therefore the fingerprint — differs per run. Always
copy the value from the **current** run's log.

### AF_XDP (optional)

Where the NIC driver supports native or generic XDP TX, the server can run
over AF_XDP instead of a plain UDP socket (root required; same flags as
`word_list`, `--skb-mode` for drivers without native XDP support):

```sh
just build
sudo ./wired_server --ifindex <n> --ip <a.b.c.d> --san-ipv4 <a.b.c.d> --skb-mode
# or: IFINDEX=<n> IP=<a.b.c.d> just run-xdp
```

Virtual NICs such as `virtio_net` (typical on KVM-based VPSes) can accept
generic-XDP TX frames without ever putting them on the wire, leaving the
server unreachable — use the plain UDP driver there.

Add `--pin-core N` to pin the process to CPU N — the XDP driver spins one
core at 100%, and pinning keeps that spin on a single cache-warm core
instead of migrating.

## Frontend

### Serve the frontend

The frontend is a separate static site — WebTransport does not require it to
be served by the same process, only from the same-origin browser tab that
opens the `WebTransport` connection to `https://localhost:4433/`. Any static
file server works; ES module `import` requires HTTP(S), not `file://`:

```sh
cd examples/webtransport_chat
just serve-frontend       # http://localhost:8000/ (local development)
```

To open the frontend from another machine (e.g. the server runs on a VPS),
plain HTTP is not enough: a non-localhost `http://` page is not a secure
context, so the browser disables the WebTransport API entirely. Serve it
over TLS instead — put a `cert.pem`/`key.pem` pair in `public/` (self-signed
is fine; accept the browser warning once):

```sh
just serve-frontend-tls   # https://<host>:8443/
```

### Connect from Chrome

Self-signed certificates fail normal CA validation, so WebTransport requires
opting in via `serverCertificateHashes` — this is what the frontend's
"Certificate hash (SHA-256)" field is for.

1. Copy the `cert sha-256 fingerprint: ...` value from the server's startup
   log (colons are fine, the frontend strips them).
2. Open `http://localhost:8000/` (the frontend, not the WebTransport server
   itself — no HTTPS needed for a plain static file server).
3. Paste the fingerprint into the "Certificate hash (SHA-256)" field, confirm
   the server URL (`https://localhost:4433/` by default), click "Connect".
4. Enter a name and message, hit "Send". Open the page in a second tab (or
   another browser window) and confirm messages sent from one tab appear in
   the other.

#### `serverCertificateHashes` constraints (read before debugging a connect failure)

The WebTransport spec requires a certificate pinned via
`serverCertificateHashes` to be an ECDSA cert with a validity period of at
most **14 days** (draft-ietf-webtrans-http3, referencing the WebRTC identity
provider security model). This sample's certificate meets it: the server
builds the self-signed leaf at startup with a validity window anchored one
hour back and spanning exactly 14 days. The flip side is that the
fingerprint changes on every restart — a connect failure after a server
restart usually means the browser still holds the previous run's hash, so
re-copy it from the current log. A very long-lived server process also
outlives its own 14-day window; restart it.

### Architecture

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

## Options

Driver selection and its flags are the SDK's `wired_srvdriver_parse`
(`src/app/http3/server/srvdriver/`), the same set as `word_list`:

| Flag | Default | Meaning |
|---|---|---|
| `--port N` | `4433` | UDP port |
| `--pin-core N` | unpinned | pin the single-process server to CPU N |
| `--workers N [--pin-cores 1]` | — | N forked worker processes (`SO_REUSEPORT`) |
| `--cores a,b,c [--control-core N]` | — | worker threads pinned to those CPUs |
| `--ifindex N [--queue N --ip a.b.c.d --skb-mode]` | — | AF_XDP driver (root) |

`--workers` cannot combine with `--cores` or `--ifindex`; `--cores` plus
`--ifindex` is AF_XDP multi-queue mode (worker *i* serves NIC queue *i*). The
drivers are covered in detail in [docs/getting-started.md](../../docs/getting-started.md).

With `--cores` (a control thread + N worker threads sharing one address
space, `src/app/http3/server/srvthreads/`), broadcast still reaches every
worker's sessions:

```sh
./wired_server --cores 0,1,2,3                  # 4 worker threads, UDP
./wired_server --cores 0,1,2,3 --control-core 4 # + control thread pinned
# combined with --ifindex: AF_XDP multi-queue, worker i serves queue i
sudo ./wired_server --ifindex <n> --cores 0,1,2,3 --ip <a.b.c.d> --san-ipv4 <a.b.c.d> --skb-mode
```

With `--workers` (forked processes, separate address spaces) a DATAGRAM is
only broadcast to sessions in the same worker process — fine for a load
demo, wrong for a chat room.

This example adds three flags of its own on top of the driver set:

| Flag | Default | Meaning |
|---|---|---|
| `--san-ipv4 a.b.c.d` | off | add an IP SAN to the self-signed certificate |
| `--qlog PATH` | off | qlog output |
| `--keylog PATH` | off | TLS key log (`SSLKEYLOGFILE` format) output |

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
- The self-signed certificate (and its fingerprint) regenerates on every
  restart with a 14-day validity window — re-copy the hash into the browser
  after each restart; see the `serverCertificateHashes` section above.
- `--cert`/`--key` (external CA certificate) are the one `word_list` flag
  pair this example's CLI does not wire — the driver flags above all work,
  but the certificate is always the fixed self-signed identity. Add
  `word_list`'s `wired_certreload_load_or_selfsigned` flow if you need a
  certificate a browser accepts without the pinning workaround.

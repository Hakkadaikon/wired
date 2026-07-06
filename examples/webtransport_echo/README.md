# WebTransport building-blocks sample

`wired_server.c` is a plain HTTP/3 server — same skeleton as
`examples/word_list` (`wired_server_run` + a `wired_srvloop_handler`
callback), libc-free, x86_64-linux, own `_start`, direct syscalls — that
additionally drives the currently-available WebTransport building blocks
once at startup and logs each step to stdout.

## Honest scope: what this demonstrates vs. what is still pending

**Real, over-the-wire, in this binary:** a normal HTTP/3 request/response
(`GET` -> `:status 200`), exactly like `word_list`. Any HTTP/3 client can
connect and get a plain-text response describing this sample.

**Real, but not wired to the network yet — exercised directly at startup
instead:**

- `wired_wt_session_*` (`src/app/webtransport/session/`) — the WebTransport
  session lifecycle state machine (unestablished -> established -> draining
  -> closed), including pre-establishment stream/datagram buffering.
- `quic_wtcapsule_encode_close` / `quic_wtcapsule_decode_close`
  (`src/app/webtransport/capsule/`) — the `WT_CLOSE_SESSION` capsule codec,
  layered on the generic RFC 9297 Capsule Protocol codec
  (`src/app/http3/core/capsule/`).
- `quic_wterrmap_to_http3` / `quic_wterrmap_from_http3`
  (`src/app/webtransport/errmap/`) — the WebTransport application error code
  <-> HTTP/3-level error code mapping (draft-ietf-webtrans-http3-15 SS8.2).

Each of these is independently implemented and unit-tested elsewhere in the
repository (`tests/app/webtransport/`). This sample calls them directly, once,
at process startup, purely so a reader can see them run in a real compiled
binary and observe the round-trips over stdout — **not** as a stand-in for
real WebTransport traffic.

**Not yet implemented, and NOT demonstrated here:** Extended CONNECT
(RFC 9220) is not routed into a `wired_wt_session`; incoming uni/bidi streams
and QUIC DATAGRAM frames are not associated with a session; there is no live
`WT_CLOSE_SESSION`/`WT_DRAIN_SESSION` capsule exchange over an actual
connection. Concretely: `grep -rn 'wired_wt_session\|quic_wtcapsule_'
src/app/http3/server/srvloop/ src/app/http3/server/srvrun/
src/transport/packet/frame/framedispatch/` returns nothing — the server's
receive loop and frame dispatcher do not call into any WebTransport code path.
A real browser or `webtransport` client library **cannot** open an
interactive WebTransport session against this server yet. That receive-side
integration (Extended CONNECT dispatch, srvloop stream-table association,
DATAGRAM-to-session delivery) is upcoming work, not shipped in this sample.

## Build and run

```sh
cd examples/webtransport_echo
nix develop          # or use the SDK's own toolchain directly
just run             # builds and starts on 0.0.0.0:4433
```

`just build` produces the `wired_server` binary (libc-free, own `_start`,
statically linked against `build/libwired.a`). On startup it prints:

```
wt-selfcheck: session unestablished->established->closed ok
wt-selfcheck: WT_CLOSE_SESSION capsule round-trip ok
wt-selfcheck: error-code mapping round-trip ok
```

then binds `0.0.0.0:4433` (or `--port`) and serves plain HTTP/3 `GET`
requests with a short text body describing this same scope. Stop it with
Ctrl-C.

Connecting with a real HTTP/3 client (e.g. `curl --http3`) gets a normal
`:status 200` response — the same wire path `word_list` demonstrates, not a
WebTransport session.

## Scope

One connection, one request stream, plain HTTP/3 only, self-signed
ECDSA P-256 / X25519 identity with fixed demo seeds (same recipe as
`word_list` — see that example's README for the external-CA-certificate
drop-in, which applies here unchanged). No Retry, Version Negotiation,
0-RTT, or connection migration. No WebTransport wire traffic — see the
scope section above.

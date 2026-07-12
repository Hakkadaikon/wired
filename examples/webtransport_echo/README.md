# WebTransport building-blocks sample

`wired_server.c` is a plain HTTP/3 server (`wired_server_run` + a request
callback — the single-process driver `examples/word_list` also runs), libc-free,
x86_64-linux, own `_start`, direct syscalls — that additionally drives the
SDK's WebTransport building blocks once at startup and logs each step to
stdout, so a reader can watch each component run in a real compiled binary.

**Looking for a live WebTransport session?** See `../webtransport_chat`,
which serves a real browser-driven session (Extended CONNECT plus DATAGRAM
send/receive over the wire). This sample only exercises the components in
isolation; no WebTransport traffic crosses the network here.

## Build and run

```sh
cd examples/webtransport_echo
nix develop          # or use the SDK's own toolchain directly
just run             # builds and starts on 0.0.0.0:4433
```

`just build` runs the SDK's own fmt+ninja+lint gate, then produces the
`wired_server` binary (libc-free, own `_start`, statically linked against
the SDK library). On startup it prints:

```
wt-selfcheck: session unestablished->established->closed ok
wt-selfcheck: WT_CLOSE_SESSION capsule round-trip ok
wt-selfcheck: error-code mapping round-trip ok
```

then binds `0.0.0.0:4433` (or `--port`) and serves plain HTTP/3 `GET`
requests with a short text body. Stop it with Ctrl-C.

## What the self-checks exercise

- `wired_wt_session_*` (`src/app/webtransport/session/`) — the session
  lifecycle state machine (unestablished -> established -> closed),
  including pre-establishment stream/datagram buffering.
- `quic_wtcapsule_encode_close` / `quic_wtcapsule_decode_close`
  (`src/app/webtransport/capsule/`) — the `WT_CLOSE_SESSION` capsule codec,
  round-tripped through the generic RFC 9297 Capsule Protocol codec
  (`src/app/http3/core/capsule/`).
- `quic_wterrmap_to_http3` / `quic_wterrmap_from_http3`
  (`src/app/webtransport/errmap/`) — the WebTransport <-> HTTP/3 error-code
  mapping (draft-ietf-webtrans-http3-15 Section 8.2).

Each component is unit-tested in `tests/app/` (`wt_session_test.c`,
`wtcapsule_test.c`, `wterrmap_test.c`); this sample calls them directly,
once, purely for observation over stdout.

## Scope

Over the wire this binary speaks plain HTTP/3 only: any HTTP/3 client
(e.g. `curl --http3`) gets a normal `:status 200` response, the same path
`word_list` demonstrates. For WebTransport on the wire, use
`../webtransport_chat`. Identity is a self-signed ECDSA P-256 / X25519
certificate with fixed demo seeds (same recipe as `word_list` — see that
example's README for the external-CA-certificate drop-in). No Retry,
Version Negotiation, 0-RTT, or connection migration.

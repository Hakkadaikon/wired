# Real-UDP HTTP/3 server sample

`wired_server.c` is a minimal HTTP/3 server that drives the in-tree server
real-wire loop (`wired_srvloop_step`) from a real client `Initial` over a real
UDP socket through a full handshake to an HTTP/3 `:status 200`, all under real
AEAD protection on the wire. It is libc-free, x86_64-linux only, and runs on
direct syscalls with its own `_start` (a static, freestanding binary).

The whole sample is driven by the single SDK header `#include "wired.h"`. A
client `Initial` is cold-started with one call, `wired_srvboot_accept` (recover
the ClientHello, build and seal the server flight); defining `WIRED_MAIN` before
the include also supplies the libc `memcpy`/`memset` a `-nostdlib` binary needs.

The wire path it owns is the whole exchange: client `Initial` → ServerHello
(Initial packet) + server flight (Handshake packet) → open the client Finished
off the wire, confirm, and seal `HANDSHAKE_DONE` → open a 1-RTT `GET` and seal a
`:status 200` back. Every packet after the Initial is opened with the peer-
direction key and every reply sealed with the server's own-direction key
(RFC 9001 5). The in-tree loopback test runs this same loop over `127.0.0.1`.

## Overview

The server drives one client `Initial` through the whole exchange to an HTTP/3
`:status 200`, every packet after the Initial under real AEAD:

1. Accept the client `Initial`, derive Initial keys from the DCID, decrypt, and
   recover the ClientHello (`wired_server_recv_initial`).
2. Negotiate ALPN `h3`, build the server flight — ServerHello / EncryptedExtensions
   (ALPN `h3` + QUIC transport parameters) / Certificate / CertificateVerify /
   Finished — and install the Handshake key (`wired_server_build_flight`), then
   seal and send the ServerHello (Initial packet) and flight (Handshake packet)
   under the server's own-direction keys (`wired_srvloop_send_initial` /
   `_send_handshake`).
3. Hand every later datagram to `wired_srvloop_step`: it opens the packet with the
   peer-direction key, verifies the client Finished and — only on a match —
   advances to the Master secret, installs 1-RTT keys and confirms, then seals
   `HANDSHAKE_DONE`. A 1-RTT `GET` is decoded (server SETTINGS first) and answered
   with a sealed `:status 200`.

The handshake is gated on a **verified** client Finished: a forged Finished
promotes nothing (the server stays unconfirmed and installs no 1-RTT keys); the
`server_test` phase machine covers that safety check directly.

The end-entity certificate is a runtime self-signed **ECDSA P-256** leaf (the
`0x0403` `ecdsa_secp256r1_sha256` CertificateVerify scheme, RFC 8446 4.4.3),
built by the server driver from its signing scalar; the in-tree client and
loopback test verify it. The ECDHE `key_share` is X25519. P-256 is chosen so the
wire certificate is acceptable to backends that reject Ed25519 server certs (see
the curl section).

## Connection flow

```mermaid
sequenceDiagram
    participant C as Client (curl --http3 / in-tree client)
    participant S as wired_server (0.0.0.0:4433)

    Note over S: listen_udp() — udp socket / bind, await ClientHello
    C->>S: Initial (long header, ClientHello in CRYPTO, ALPN h3, X25519 key_share)
    Note over S: wired_server_recv_initial() — derive Initial keys from DCID,<br/>decrypt, fold ClientHello into the transcript
    Note over S: wired_server_build_flight()<br/>SH / EE(ALPN h3 + transport params) /<br/>Cert(ECDSA P-256) / CertVerify(0x0403) / Finished<br/>+ install Handshake key
    S-->>C: ServerHello (Initial packet)
    S-->>C: server flight (Handshake packet)
    C->>S: client Finished (Handshake, AEAD-protected)
    Note over S: wired_srvloop_step() — open with CLIENT_HS,<br/>verify client Finished,<br/>only on a match: Master secret + 1-RTT keys + confirm
    S-->>C: HANDSHAKE_DONE (1-RTT, SERVER_AP)
    Note over S,C: 1-RTT confirmed
    C->>S: HEADERS (GET /, 1-RTT, CLIENT_AP)
    Note over S: wired_srvloop_step() — SETTINGS first,<br/>wired_h3srv_on_request() decode, build :status 200
    S-->>C: HEADERS (:status 200, 1-RTT, SERVER_AP)
```

The handshake is gated on a verified client Finished: a forged Finished promotes
nothing (the server stays unconfirmed and never installs 1-RTT keys). SETTINGS is
sent before any response, and a response is built only after a request HEADERS
has been decoded (RFC 9114 6.2.1 / 4.1). The sample drives this whole exchange
over its own socket via `wired_srvloop_step`; the in-tree loopback test runs the
same loop over `127.0.0.1`.

## Build and run

```sh
cd examples/word_list
nix develop          # provides clang / just / tcpdump
just run             # builds and starts on 0.0.0.0:4433
```

`just build` alone produces the `examples/word_list/wired_server` binary (libc-free, own
`_start`). On startup the server prints `listening on 0.0.0.0:4433` and waits for
the ClientHello. Stop it with Ctrl-C.

## Connecting with `curl --http3`

Run the server on a host where the client can reach UDP `4433`, then:

```sh
curl --http3 --insecure https://<host>:4433/
```

Expected output includes:

```
< HTTP/3 200
```

This was **confirmed on a real external host** (a VPS, not this sandbox): a real
`curl --http3` linked against the **quiche** backend (BoringSSL) completed the
QUIC + TLS 1.3 handshake against this sample and received `HTTP/3 200` for the
`GET`, with the connection closing normally. Scope and caveats, stated honestly:

- **quiche backend confirmed; other backends not.** The completed run used
  curl's quiche/BoringSSL backend. The sample signs with ECDSA P-256 (`0x0403`),
  which BoringSSL accepts where it rejects Ed25519 server certs by default — P-256
  is chosen to clear that hurdle. curl's **ngtcp2** backend (GnuTLS / OpenSSL)
  applies a different MTI / extension set and was **not** exercised, so completion
  there is **not** claimed; it needs separate verification.
- **External host, not this sandbox.** The curl in this sandbox is built
  **without** HTTP/3 (`curl --version` lists no `http3`), so the run was done on a
  separate VPS, not here. Likewise `tcpdump -i lo -n udp port 4433` needs
  `CAP_NET_RAW`, unavailable in the sandbox.
- **One connection, one `GET`.** A single `GET /` answered with `:status 200`;
  no multi-request, no `POST` body, no migration.

## First-choice verification: the in-tree client over loopback

The positive, in-environment check is the repository's own server real-wire loop
(`src/srvloop/`, `src/srvwire/`) driving this exchange over a real UDP loopback
socket (`127.0.0.1`), end to end:

```sh
cd ..
just test
```

The `h3_loopback` test checks, without any external HTTP/3 tooling and without
`CAP_NET_RAW` (it gracefully skips the socket leg when the sandbox forbids
sockets):

1. the client's real protected Initial crosses a loopback UDP socket and arrives
   padded to 1200 bytes (RFC 9000 14.1);
2. a real AEAD-protected client Finished crosses the socket and
   `wired_srvloop_step` opens it with the peer-direction key, confirms the server,
   and seals a `HANDSHAKE_DONE` the peer opens with `SERVER_AP`;
3. a real 1-RTT `GET` crosses the socket and the step seals a `:status 200` the
   peer opens with `SERVER_AP` (RFC 9114 4.1).

The client peer in the test shares the server's key schedule, so seal-then-open
across the wire is identity (RFC 9001 5); the forged-Finished safety check lives
in `server_test`, and the full `src/client/` mutual handshake is exercised in
`client_test`.

## What is verified / what is not

**Verified (demonstrated):**

- **Build**: `cd examples/word_list && just build` produces the `wired_server` binary
  (libc-free, own `_start`).
- **Bind + listen**: `./wired_server` prints `listening on 0.0.0.0:4433` and waits
  for the ClientHello (bind succeeds, no crash).
- **Sample real-wire path**: the sample recovers the ClientHello, seals + sends
  the ServerHello (Initial) and flight (Handshake), then drives
  `wired_srvloop_step` on every later datagram — opening it with the peer key,
  confirming on a verified Finished, and sealing `HANDSHAKE_DONE` and a 200.
- **Loopback datagram delivery**: a real protected Initial crosses a loopback UDP
  socket and arrives padded to 1200 (`h3_loopback`, check 1).
- **Real-wire handshake confirmation**: a real AEAD-protected client Finished
  crosses a loopback socket and `wired_srvloop_step` opens it, confirms, and seals
  `HANDSHAKE_DONE` (`h3_loopback`, check 2; `srvloop_test` for the buffer-path
  equivalent; `server_test` for the full phase machine).
- **Real-wire HTTP/3 GET → 200**: a real 1-RTT `GET` crosses the socket and the
  step seals a `:status 200` the peer opens with `SERVER_AP` (`h3_loopback`,
  check 3).
- **Real `curl --http3` completion**: on a real external host (VPS), a real
  `curl --http3` (quiche / BoringSSL backend) completed the handshake against this
  sample and received `HTTP/3 200` for the `GET`, the connection closing normally.
  This was **not** run in this sandbox (no HTTP/3 curl here) and covers the quiche
  backend only.
- **Forged-Finished safety**: a forged client Finished promotes nothing; the
  server stays unconfirmed and installs no 1-RTT keys (`server_test`,
  `srvloop_test`).
- **Wire format**: the long header conforms to RFC 9000 17.2, the TLS flight to
  RFC 8446 4.4, and the in-tree tests confirm the bytes match the RFC 9001 A.2
  vector.

**Not verified (out of scope or environment-limited):**

- **The full `src/client/` mutual handshake against this sample over the wire**:
  the `h3_loopback` peer shares the server's key schedule rather than running the
  client orchestrator's own certificate verification end to end. The sample's
  real-wire loop (open / confirm / seal) is exercised; pairing it with the full
  `src/client/` handshake over a socket is not.
- Completion against curl's **ngtcp2** backend (GnuTLS / OpenSSL) or other HTTP/3
  clients (Chrome, etc.) — only the **quiche** backend was confirmed; ngtcp2's
  differing MTI / extension set needs separate verification.
- A `tcpdump` packet capture — no `CAP_NET_RAW` in this environment.
- More than one connection or request stream; methods other than `GET`
  (e.g. `POST` with a request body).

## Scope

One connection, one request: a single `GET` answered with `:status 200`. The
ECDHE `key_share` is X25519 and the certificate/CertificateVerify use ECDSA
P-256 (`0x0403`). No Retry, Version Negotiation, 0-RTT, or connection migration.
The
handshake keys and certificate use fixed seeds for reproducibility; a production
server would derive per-run keys.

## Using an external CA-issued certificate chain

Drop `cert.pem` and `key.pem` next to the binary (the server reads them from
the cwd at startup):

```sh
cp /etc/letsencrypt/live/example.com/fullchain.pem cert.pem
cp /etc/letsencrypt/live/example.com/privkey.pem  key.pem
./wired_server
```

Prerequisites:

- Certificate and key are **ECDSA P-256** (RSA and Ed25519 are not supported —
  signing matches the SDK's fixed `quic_p256sign_sign` primitive). The key may
  be a SEC1 `EC PRIVATE KEY` or an unencrypted PKCS#8 `PRIVATE KEY`.
- `cert.pem` is a fullchain, leaf first, at most 2 certificates (leaf + one
  intermediate).
- No files → the server starts with its runtime self-signed certificate as
  before (`self-signed (no cert.pem)`). A broken or half-present pair makes
  the server die at startup instead of silently falling back to self-signed.

A Handshake flight larger than one MTU datagram is split across several
datagrams automatically, so a real chain fits.

The SDK does not check that the key matches the chain's leaf public key —
that agreement is the caller's responsibility. A mismatch is not silently
accepted: the client's CertificateVerify signature check fails and the
handshake does not complete.

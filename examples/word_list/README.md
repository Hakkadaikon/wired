# word_list — a libc-free HTTP/3 server

A minimal HTTP/3 server built on the wired SDK: a static, freestanding
x86_64-linux binary on direct syscalls, no libc. By default it is a message-log
demo — `POST` appends the body to an in-memory log and echoes it back, `GET`
returns the whole log — and with `--root` it serves static files instead. The
SDK (`wired_srvdriver_run`) owns bind, handshake, HTTP/3, and the I/O drivers;
`wired_server.c` supplies only the application callback and CLI configuration.

## Build & run

```sh
cd examples/word_list
just run             # build + listen on 0.0.0.0:4433 (Ctrl-C to stop)
```

Other recipes: `just build` (binary only), `just build-debug` / `just run-debug`
(trace logging via `-DQUIC_DEBUG`), `just run-workers` (4 worker processes, one
pinned per core), `just run-xdp` (AF_XDP; root, needs `$IFINDEX`, `$IP`, and a
`cert.pem`/`key.pem` pair in the cwd — it passes `--cert`/`--key`).

## Verify

```sh
curl --http3-only --insecure https://<host>:4433/ -d 'hello'  # POST: echoes it
curl --http3-only --insecure https://<host>:4433/             # GET: whole log
```

A real `curl --http3` (quiche backend) on an external host has completed the
QUIC + TLS 1.3 handshake against this server and received `HTTP/3 200`.

## Options

| Flag | Default | Meaning |
|---|---|---|
| `--port N` | `4433` | UDP port |
| `--root DIR` | off | static file mode (absent: message-log demo) |
| `--index NAME` | `index.html` | index file for directory requests |
| `--access-log PATH` | off | one line per request: `METHOD PATH STATUS BYTES` |
| `--cert PATH` / `--key PATH` | self-signed | PEM certificate and key (below) |
| `--qlog-file PATH` / `--keylog-file PATH` | off | qlog / TLS key log output |
| `--busy-poll 1` | off | spin the receive loop instead of blocking in `poll(2)` |
| `--pin-core N` | unpinned | pin the single-process server to CPU N |
| `--workers N [--pin-cores 1]` | — | N forked worker processes (`SO_REUSEPORT`) |
| `--cores a,b,c [--control-core N]` | — | worker threads pinned to those CPUs |
| `--ifindex N [--queue N --ip a.b.c.d --skb-mode]` | — | AF_XDP driver (root) |

`--workers` cannot combine with `--cores` or `--ifindex`, and `--pin-core`
cannot combine with `--workers` or `--cores` (they have their own pinning
flags); `--cores` plus `--ifindex` is AF_XDP multi-queue mode (worker *i*
serves NIC queue *i*). The drivers are covered in detail in
[docs/getting-started.md](../../docs/getting-started.md).

## Certificates

Without `--cert`/`--key` the server runs with a runtime self-signed ECDSA P-256
certificate. To drop in a real one, pass `--cert cert.pem --key key.pem`:
`cert.pem` is a fullchain PEM, leaf first, at most 2 certificates; the key is a
P-256 private key (SEC1 or unencrypted PKCS#8) — RSA and Ed25519 are not
supported. `SIGHUP` hot-reloads the pair from the same paths. A failing load
makes the server die at startup instead of silently falling back to self-signed.

## Limitations

- `SO_REUSEPORT`/RSS route packets by 4-tuple hash, which cannot follow QUIC
  connection migration: after a migration, packets can land on a worker that
  does not know the connection (`--workers` and `--cores` alike).
- The plain `--ifindex` driver expects a single-queue NIC; for a multi-queue
  NIC, add `--cores` with one CPU per queue.
- AF_XDP does not support MTU > 1500; on `veth` and similar interfaces, add
  `--skb-mode` (generic XDP).
- Virtual NICs such as `virtio_net` may fail to transmit under generic XDP —
  prefer the plain UDP driver there.

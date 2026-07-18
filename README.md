# wired

**An HTTP/3 + WebTransport server SDK in C that runs the entire protocol
stack in user space — with zero dependencies. No OpenSSL, no libevent, not
even libc.**

[![CI](https://github.com/Hakkadaikon/wired/actions/workflows/ci.yml/badge.svg)](https://github.com/Hakkadaikon/wired/actions/workflows/ci.yml)
[![Fuzz](https://github.com/Hakkadaikon/wired/actions/workflows/fuzz.yml/badge.svg)](https://github.com/Hakkadaikon/wired/actions/workflows/fuzz.yml)
[![Docs](https://github.com/Hakkadaikon/wired/actions/workflows/docs.yml/badge.svg)](https://github.com/Hakkadaikon/wired/actions/workflows/docs.yml)
[![MIT Licensed](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Quick start

Three commands to a running HTTP/3 server. (`just` is a command runner —
think `make` without the Makefile quirks. The first command installs
everything else.)

```sh
just setup           # one-time: installs the toolchain (via Nix)
just build           # format + compile + lint

cd examples/word_list
just run             # serves HTTP/3 on 0.0.0.0:4433
```

Test it from any machine that can reach UDP port 4433 — the Docker image
saves you from needing an HTTP/3-capable curl locally:

```sh
docker run --rm ymuski/curl-http3 \
    curl --http3-only --insecure -v https://<host>:4433/
```

That's it. [Getting Started](docs/getting-started.md) walks through the same
thing step by step and takes you from here to a server of your own.

## What is this for?

- **Embedding an HTTP/3 / WebTransport server** in a project where you don't
  want a dependency chain — the whole SDK is one static library.
- **Learning how QUIC actually works.** Every layer, from the TLS handshake
  to congestion control to the bytes on the wire, is readable C in this one
  repository, each file annotated with the RFC section it implements.
- **Running interop and network experiments** — four interchangeable I/O
  drivers (from a simple `poll` loop up to kernel-bypass AF_XDP) behind one
  command-line switch.

You don't need to be a protocol expert to start: the quick start above and
the [examples](examples/) run as-is. The internals documentation is there
for when (and if) you want to go deeper.

## Why wired?

**Zero dependencies, zero libc.** Every file compiles under
`-ffreestanding -nostdlib` — no standard library at all. If something
external leaked in, the build would fail. That *is* the proof.

**The full stack in user space.** QUIC, TLS 1.3, HTTP/3, QPACK, and
WebTransport are all implemented here. The kernel only ever carries
already-encrypted UDP bytes.
(Specs: [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) /
[9001](https://www.rfc-editor.org/rfc/rfc9001) /
[9002](https://www.rfc-editor.org/rfc/rfc9002) /
[8446](https://www.rfc-editor.org/rfc/rfc8446) /
[9114](https://www.rfc-editor.org/rfc/rfc9114) /
[9204](https://www.rfc-editor.org/rfc/rfc9204) /
[draft-ietf-webtrans-http3](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/) —
the [full list](docs/arch/rfcs.md) covers 40+ specifications.)

**Four I/O drivers behind one flag.** The same callback runs single-process
(`poll`), forked workers, raw threads, or kernel-bypass AF_XDP. Switching
is a command-line flag, not a code change.

**Its own verified cryptography.** AES-GCM, ChaCha20-Poly1305, X25519,
Ed25519, ECDSA P-256/P-384, RSA, SHA-2, HKDF — each checked against the
official RFC/FIPS test vectors.

**Auditable by construction.** Every function stays below a hard complexity
limit (CI-enforced). CERT C lint on every push, nightly fuzzing, and interop
tests against real QUIC clients.

## What the code looks like

Your side of a server is **one callback**. The SDK owns everything else:
bind, handshake, encryption, loss recovery, HTTP/3.

```c
/* Called once per HTTP/3 request. Fill body_out, return 1. */
static int app_on_request(
    void* ctx, const wired_h3reqdrive_req* req,   /* method, path, body */
    quic_obuf* body_out, const char** content_type) {
  /* ... write your response into body_out ... */
  return 1;
}
```

Then `main` is three calls — load an identity, parse the flags, run:

```c
int wired_main(int argc, char** argv) {
  server_identity(&id);                            /* keys + certificate  */
  wired_srvdriver_parse(argc, argv, &opt);         /* --port, --workers…  */
  wired_srvdriver_run(&id, handler, obs, &opt);    /* serve until SIGTERM */
  return 0;
}
```

(Declarations and error handling trimmed for the README —
[examples/word_list](examples/word_list/wired_server.c) is the complete,
runnable version.)

The same binary then picks its I/O driver from the command line: no flags
for a single process, `--workers N` for forked workers on one port,
`--cores a,b,c` for a thread fan-out, `--ifindex N --ip a.b.c.d` for AF_XDP.

## Examples

| Example | What it shows |
|---|---|
| [word_list](examples/word_list/) | HTTP/3 message log (POST/GET) or static-file server; all four I/O drivers; CA-certificate drop-in |
| [webtransport_chat](examples/webtransport_chat/) | Browser chat: live WebTransport sessions, DATAGRAM broadcast to every client, framework-free JS frontend |
| [webtransport_echo](examples/webtransport_echo/) | The WebTransport building blocks (session lifecycle, capsules, error mapping) driven in isolation |
| [webtransport_interop](examples/webtransport_interop/) | The [quic-interop-runner](https://github.com/quic-interop/quic-interop-runner) WebTransport server endpoint: file transfer over streams and DATAGRAMs against real client implementations |

## Documentation

Everything lives under [docs/](docs/README.md) — one index page ordering
every doc by task. First read:
[Getting Started](docs/getting-started.md), then
[Architecture](docs/arch/overview.md).

## Supported platform

x86_64-linux only. The AF_XDP driver additionally needs root and kernel 5.9
or later (`BPF_LINK_CREATE` for XDP); on NICs without native XDP,
`--skb-mode` selects generic XDP —
note that some virtualized drivers (e.g. `virtio_net`) do not deliver AF_XDP
TX in generic mode, so prefer the plain UDP driver there.

## License

MIT — see [LICENSE](LICENSE).

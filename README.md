# wired

`wired` is a libc-free QUIC / HTTP/3 / WebTransport server SDK in C for
x86_64-linux, featuring:

- **zero dependencies, zero libc** — every source compiles under
  `-ffreestanding -nostdlib`, talks to the kernel through raw syscalls only,
  and ships its own `_start`. The compile itself is the proof: if a file
  needs a standard header, the build fails
- **the full stack in user space** — QUIC ([RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) /
  [9001](https://www.rfc-editor.org/rfc/rfc9001) / [9002](https://www.rfc-editor.org/rfc/rfc9002)),
  TLS 1.3 ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)),
  HTTP/3 ([RFC 9114](https://www.rfc-editor.org/rfc/rfc9114)),
  QPACK ([RFC 9204](https://www.rfc-editor.org/rfc/rfc9204)), and
  WebTransport ([draft-ietf-webtrans-http3](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/));
  the kernel only carries already-encrypted UDP bytes
- **four I/O drivers behind one CLI** — single-process `poll`, multi-process
  fork (`SO_REUSEPORT`), multi-thread fan-out (raw `clone`/`futex`, no
  pthreads), and AF_XDP (packets polled from a shared UMEM ring, zero
  per-packet receive syscalls)
- **its own verified cryptography** — AES-128-GCM, ChaCha20-Poly1305, X25519,
  Ed25519, ECDSA P-256/P-384, RSA, SHA-2, HKDF — each checked against its
  published RFC/FIPS vectors
- **auditable by construction** — every function holds cyclomatic complexity
  ≤ 3 (lizard-enforced in CI), clang-tidy CERT C rules on every push, three
  libFuzzer harnesses run nightly, and a
  [quic-interop-runner](https://github.com/quic-interop/quic-interop-runner)
  server endpoint is included

See the [API reference](https://hakkadaikon.github.io/wired/),
[examples](examples/), and [Getting Started](docs/getting-started.md) to get
started with `wired`.

[![CI](https://github.com/Hakkadaikon/wired/actions/workflows/ci.yml/badge.svg)](https://github.com/Hakkadaikon/wired/actions/workflows/ci.yml)
[![Fuzz](https://github.com/Hakkadaikon/wired/actions/workflows/fuzz.yml/badge.svg)](https://github.com/Hakkadaikon/wired/actions/workflows/fuzz.yml)
[![Docs](https://github.com/Hakkadaikon/wired/actions/workflows/docs.yml/badge.svg)](https://github.com/Hakkadaikon/wired/actions/workflows/docs.yml)
[![MIT Licensed](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Quick start

```sh
just setup           # one-time: installs Nix if absent
just build           # format + freestanding compile + lint

cd examples/word_list
just run             # binds 0.0.0.0:4433

# from any machine that can reach UDP 4433:
docker run --rm ymuski/curl-http3 \
    curl --http3-only --insecure -v https://<host>:4433/
```

## Example

The application side of a server is one callback plus one run call; the SDK
owns everything else — bind, handshake, packet protection, loss recovery,
HTTP/3, and the I/O driver selected at startup. Condensed from
[examples/word_list](examples/word_list/wired_server.c):

```c
#define WIRED_MAIN /* emits the libc shim + _start a -nostdlib binary needs */
#include "wired.h"
#include "app/http3/server/srvdriver/srvdriver.h"
#include "common/platform/exit/exit.h" /* wired_die */

static int app_on_request(
    void* ctx, const wired_h3reqdrive_req* req,
    quic_obuf* body_out, const char** content_type) {
  /* answer req (method/path/body views) by filling body_out */
  return 1;
}

int wired_main(int argc, char** argv) {
  wired_srvboot_id     id;
  wired_srvdriver_opt  opt;
  wired_srvrun_handler h   = {app_on_request, 0};
  wired_srvrun_obs     obs = {0};

  server_identity(&id); /* keys + self-signed cert seed, see examples/ */
  if (!wired_srvdriver_parse(argc, argv, &opt)) wired_die("bad flags\n");
  if (!wired_srvdriver_run(&id, h, obs, &opt)) wired_die("listen failed\n");
  return 0;
}
```

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

Full index: [docs/README.md](docs/README.md).

- [Getting Started](docs/getting-started.md) — build, test, run the
  examples, and use the SDK in your own application.
- [Architecture](docs/arch/overview.md) — the user-space/kernel boundary,
  the five layers, and the send/receive/handshake data flows; with
  [per-layer detail](docs/arch/layers.md) and the
  [implemented specifications](docs/arch/rfcs.md).
- [Development](docs/development.md) — the constraints every change must
  hold (libc-free, CCN ≤ 3, unity build) and how to add a domain.
- [Security](docs/security.md) — the security properties the SDK enforces,
  by subsystem, and the checks left to the caller.
- [Syscalls](docs/syscalls.md) — every syscall the SDK issues, and why.
- [API stability](docs/api-stability.md) — which public functions are the
  stable application-facing surface, and which are low-level internals.
- [API reference](https://hakkadaikon.github.io/wired/) — doxygen for the
  public `wired.h` surface, regenerated on every push to `main`.

## Supported platform

x86_64-linux only. The AF_XDP driver additionally needs root and kernel 5.9
or later (`BPF_LINK_CREATE` for XDP); on NICs without native XDP,
`--skb-mode` selects generic XDP —
note that some virtualized drivers (e.g. `virtio_net`) do not deliver AF_XDP
TX in generic mode, so prefer the plain UDP driver there.

## License

MIT — see [LICENSE](LICENSE).

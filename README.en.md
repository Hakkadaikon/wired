# wired

[日本語](README.md)

A server SDK for QUIC, HTTP/3, WebTransport and Media over QUIC Transport (MoQT), written in C. It has no external dependencies: no OpenSSL, no libevent, no libc.

This page is a short overview. The full README and everything under `docs/` are written in Japanese.

## 1. Overview

| Item | Content |
|---|---|
| Protocols | TLS 1.3 and its cryptography, QUIC, HTTP/3 and QPACK, WebTransport, MoQT (draft-18/19/22/23) |
| Scope | All of the above implemented in user space in this repository |
| Role | Server only. The client role is out of scope |
| Dependencies | None. Every file compiles with `-ffreestanding -nostdlib` |
| Memory | No `malloc` / `free`. Fixed-size tables, static or mapped once at startup |
| Output | One static server binary |
| Platform | x86_64 Linux |
| License | MIT |

## 2. Build and run

The toolchain is pinned by a Nix flake. Every build and check goes through a `just` recipe.

1. Install Nix with flakes enabled.
2. Build every source and the examples: `nix develop -c just ninja`
3. Run the tests: `nix develop -c just test`

The details are in [docs/standards/setup.md](docs/standards/setup.md) (Japanese).

## 3. Examples

| Example | Content |
|---|---|
| [word_list](examples/word_list/) | HTTP/3 message log (POST/GET) or static file server. Runs on all four I/O drivers (poll, fork, threads, AF_XDP) |
| [moqt_chat](examples/moqt_chat/) ([live demo](https://hakkadaikon.github.io/wired/moqt_chat)) | Browser chat and voice room over MoQT |
| [webtransport_interop](examples/webtransport_interop/) | WebTransport server endpoint for [quic-interop-runner](https://github.com/quic-interop/quic-interop-runner) |
| [moqt_interop](examples/moqt_interop/) | MoQT relay for [moq-interop-runner](https://github.com/englishm/moq-interop-runner) |

An application writes one callback; the SDK owns the event loop, the handshake, packet protection, loss recovery and HTTP/3. See the excerpt in [README.md section 6](README.md#6-コードの例).

## 4. Documentation

| Document | Language | Content |
|---|---|---|
| [README.md](README.md) | Japanese | Design, quality gates, performance figures, interop results |
| [docs/](docs/README.md) | Japanese | Architecture, requirement ledgers, security design, known limitations |
| [Interactive guide](https://hakkadaikon.github.io/wired/guide/ja/) | Japanese | Step-by-step path to a running server |
| [API reference](https://hakkadaikon.github.io/wired/) | English | Generated from the header comments |
| [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) | — | Contribution rules and vulnerability reporting |

## 5. License

MIT. See [LICENSE](LICENSE).

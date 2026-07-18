# wired documentation

**Start here:** [Getting Started](getting-started.md), then
[Architecture](arch/overview.md), then whatever your task needs below.

## Learn it

- [Getting Started](getting-started.md) — build, run, write your first server.
- [examples/](../examples/) — four runnable servers, smallest first.

## Understand it

- [Architecture](arch/overview.md) — the big picture and the data flows.
- [The Layers](arch/layers.md) — each layer, one section at a time.
- [Specifications](arch/rfcs.md) — every RFC the SDK implements, and why.

## Use it as a dependency

- [API Stability](api-stability.md) — which functions are safe to build on.
- [API reference](https://hakkadaikon.github.io/wired/) — full doxygen.
- [Syscalls](syscalls.md) — every kernel call the SDK makes.
- [Security](security.md) — what the SDK guarantees, what it leaves to you.

## Change it

- [Development](development.md) — the rules every change must hold, and how
  to add code.

## Glossary

Terms the documentation uses without stopping to re-explain each time:

| Term | Meaning |
|---|---|
| **QUIC** | The encrypted, multiplexed transport protocol over UDP that HTTP/3 runs on (RFC 9000). |
| **HTTP/3** | HTTP mapped onto QUIC streams instead of TCP (RFC 9114). |
| **WebTransport** | Browser-facing API for low-latency bidirectional streams and datagrams over HTTP/3. |
| **QPACK** | HTTP/3's header-compression scheme, designed to survive out-of-order stream delivery (RFC 9204). |
| **DATAGRAM** | A QUIC frame that trades reliability for latency — sent once, never retransmitted (RFC 9221). |
| **libc-free / freestanding** | Compiled with `-ffreestanding -nostdlib`: no C standard library, no CRT; the SDK makes raw syscalls and ships its own `_start`. |
| **AF_XDP** | A Linux socket family that delivers raw packets to user space via shared memory rings, bypassing most of the kernel network stack. |
| **`SO_REUSEPORT`** | A socket option letting multiple processes bind the same port; the kernel load-balances incoming packets among them. |
| **unity build** | Compiling the whole test suite as one translation unit (`tests/run.c` `#include`s every `.c`), so all symbols share one namespace. |
| **CCN** | Cyclomatic complexity number — the count of independent paths through a function. This repo caps it at 3 per function. |
| **qlog** | A structured JSON logging format for QUIC events, readable by tools like qvis. |
| **cwnd / congestion window** | How many bytes the sender may have in flight, grown and shrunk by the congestion-control algorithm. |
| **AEAD** | Authenticated encryption (e.g. AES-GCM): ciphers that both encrypt and detect tampering. |
| **HKDF** | The key-derivation function TLS 1.3 uses to turn one shared secret into all the session keys (RFC 5869). |

`sdk/` in this directory is doxygen output (gitignored, published to the API
reference above) — edit header doc comments, not the generated HTML.

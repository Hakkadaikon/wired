# wired documentation

Documentation is organized by what you are trying to do. Each page stands
alone; this index is the map.

**Recommended first read:** [Getting Started](getting-started.md) →
[Architecture and Data Flow](arch/overview.md) → whichever reference page
your task needs. Every page ends with a "Next" pointer so you are never at a
dead end.

## Learn it (first session)

1. [Getting Started](getting-started.md) — prerequisites, build and test,
   run an example, then a minimal server of your own. Also covers choosing
   an I/O driver, WebTransport callbacks, certificates, and observability.
2. [examples/](../examples/) — four runnable servers, smallest first:
   `word_list` (HTTP/3), `webtransport_echo`, `webtransport_chat`,
   `webtransport_interop`.

## Understand it (architecture)

- [Architecture and Data Flow](arch/overview.md) — the user-space/kernel
  boundary, the five layers, and the send / receive / handshake flows.
- [The Layers](arch/layers.md) — each layer's problem, dependencies, and key
  design points, one section per layer.
- [Implemented Specifications](arch/rfcs.md) — every RFC / FIPS / draft the
  SDK implements, grouped, with why each one is needed.

## Use it as a dependency (reference)

- [API Stability](api-stability.md) — which public functions are the stable
  application-facing surface and which are low-level internals, plus the
  versioning policy.
- [API reference](https://hakkadaikon.github.io/wired/) — doxygen for the
  public `wired.h` surface, regenerated on every push to `main`.
- [Syscalls](syscalls.md) — the complete list of syscalls the SDK issues,
  with why each one is needed and where it is called.
- [Security](security.md) — the security properties the SDK enforces, by
  subsystem, and the checks left to the caller.

## Change it (contributing)

- [Development](development.md) — the design philosophy, the build system,
  the hard constraints every change must hold (libc-free, CCN ≤ 3, unity
  build), and the workflow for adding a domain.

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

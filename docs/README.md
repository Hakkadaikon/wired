# wired documentation

Documentation is organized by what you are trying to do. Each page stands
alone; this index is the map.

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

`sdk/` in this directory is doxygen output (gitignored, published to the API
reference above) — edit header doc comments, not the generated HTML.

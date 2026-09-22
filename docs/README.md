# wired documentation

**Start here:** [Getting Started](getting-started.md), then
[Architecture](arch/overview.md), then whatever your task needs below.

## Learn it

- [Getting Started](getting-started.md) — build, run, write your first server.
- [examples/](../examples/) — five runnable servers, smallest first.

## Understand it

- [Architecture](arch/overview.md) — the big picture and the data flows.
- [The Layers](arch/layers.md) — each layer, one section at a time.
- [Specifications](arch/rfcs.md) — every RFC the SDK implements, and why.

## Use it as a dependency

- [API Stability](api-stability.md) — which functions are safe to build on.
- [API reference](https://hakkadaikon.github.io/wired/) — full doxygen.
- [Syscalls](syscalls.md) — every kernel call the SDK makes.
- [Security](security.md) — what the SDK guarantees, what it leaves to you.
- [Test Coverage](test-coverage.md) — how far each spec is tested, from
  unit vectors to real-client interop, checkbox by checkbox.
- [Features](features/README.md) — per-spec EARS requirement ledgers (43
  RFCs/FIPS/SPs/drafts), each requirement mapped to its test or its gap.
- [Interop Results](interop.md) — cross-implementation runs against
  quic-go and webtransport-go.
- [Comparison](performance/comparison.md) — features and measured speed versus other
  HTTP/3 / WebTransport / MOQT implementations, under pinned conditions.
- [Performance Monitoring](performance/monitoring.md) — a 5-hour resource
  baseline (CPU/memory/network) for the `moqt_chat` example server, and the
  test machine's `lscpu`.

## Change it

- [Development](development.md) — the rules every change must hold, and how
  to add code.

`sdk/` in this directory is doxygen output (gitignored, published to the API
reference above) — edit header doc comments, not the generated HTML.

# quic_vibe

quic_vibe is a libc-free SDK for QUIC / TLS 1.3 / HTTP/3.
It calls x86_64 Linux syscalls directly, supplies its own `_start`, and uses neither the standard library nor any external dependency.
The only thing it leaves to the kernel is raw UDP I/O; packet framing, encryption, loss recovery, congestion control, streams, and HTTP/3 are all implemented in user space.

## Documentation

- [docs/arch/overview.md](docs/arch/overview.md): the boundary between user space and the kernel, the five layers, and the data flow for sending, receiving, and the handshake.
- [docs/arch/layers.md](docs/arch/layers.md): the problem each of the common / crypto / transport / tls / app layers solves and the key points of its design.
- [docs/arch/rfcs.md](docs/arch/rfcs.md): the list of implemented RFCs and FIPS publications, and why each specification is needed.
- [docs/usage.md](docs/usage.md): the build and the `just` targets, the source layout, and how to use the library.
- [docs/development.md](docs/development.md): the development constraints and workflow, and how to add a domain.
- [docs/security.md](docs/security.md): the security properties the SDK enforces, by subsystem, and the checks left to the caller.

## Quick start

```sh
just build    # compile each domain freestanding
just ninja    # incremental, parallel build
just test     # run the test suite
just check    # the CCN gate and the test suite
```

## License

MIT — see [LICENSE](LICENSE).

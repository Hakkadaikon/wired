# quic_vibe

A libc-free QUIC SDK in C, built directly on x86_64 Linux syscalls.

It covers the QUIC transport wire format and state machines, a from-scratch
cryptography stack (AES-128-GCM, ChaCha20-Poly1305, HKDF, X25519, header
protection), the TLS 1.3 key schedule, loss recovery and congestion control,
and a userspace IPv4/UDP stack. An end-to-end handshake runs entirely in user
space over an in-memory link — no sockets, no kernel network stack. Every
function stays within cyclomatic complexity 3, and every codec is checked
against the official RFC/FIPS test vectors.

## Quick start

```sh
nix develop        # clang + just + lizard
just check         # run the CCN gate and the full test suite
```

`just build` compiles every domain under `-ffreestanding -nostdlib` (proving
it is libc-free); `just test` runs the hosted assertion suite.

## Documentation

- [docs/usage.md](docs/usage.md) — building, the `just` targets, the source
  layout, and how to use the library (including the kernel-free end-to-end
  flow).
- [docs/development.md](docs/development.md) — the hard constraints, the
  test-first workflow, and how to add a domain.

## License

MIT — see [LICENSE](LICENSE).

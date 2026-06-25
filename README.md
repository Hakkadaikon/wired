# quic_vibe

A libc-free QUIC SDK in C, built directly on x86_64 Linux syscalls.

This is the wire-format and state-machine core of QUIC ([RFC 9000]): packet
and frame codecs plus the stream and connection state machines. The
cryptographic handshake (RFC 9001) and loss/congestion control (RFC 9002)
are out of scope for now (see [Scope](#scope)).

[RFC 9000]: https://www.rfc-editor.org/rfc/rfc9000.html

## Design

- **No libc, no CRT.** Every domain compiles `-ffreestanding -nostdlib`.
  System calls go straight through inline assembly (`src/sys/syscall.h`),
  and the entry point is a freestanding `_start`.
- **x86_64 Linux only.** No portability layer.
- **One domain per directory.** Each is independently testable.
- **Cyclomatic complexity ≤ 3** for every function, enforced by `lizard`.
  Branch-heavy logic (header parsing, packet-number recovery, state
  transitions) is factored into small helpers and driven by tables.

## Layout

```
src/
  sys/      x86_64 direct syscalls, freestanding entry, base types
  varint/   variable-length integer codec + TLV cursor helpers   (RFC 9000 §16)
  packet/   long/short header parse/build; packet number          (RFC 9000 §17,
            truncation and recovery                                A.2/A.3)
  tparam/   transport parameter TLV codec                          (RFC 9000 §18)
  frame/    PADDING/PING/CRYPTO/STREAM/CONNECTION_CLOSE codec      (RFC 9000 §19)
  fsm/      shared table-driven finite state machine engine
  stream/   sending/receiving stream state machines               (RFC 9000 §3)
  conn/     handshake lifecycle + per-space packet numbers         (RFC 9000 §12)
tests/      hosted assert-based test harness, one file per domain
```

## Build

A Nix flake provides the toolchain (`clang`, `just`, `lizard`):

```sh
nix develop
```

Then use `just`:

```sh
just build   # compile every domain freestanding into build/*.o
just test    # build and run the hosted test suite
just ccn     # fail if any function exceeds CCN 3
just check   # ccn + test
```

`just build` proves libc independence: all domains compile under
`-ffreestanding -nostdlib`. `just test` builds the same sources in a hosted
configuration so they can be exercised with assertions.

## Correctness

Codecs are checked against the RFC 9000 Appendix A sample vectors, and every
codec has round-trip and truncated-input tests. The packet-number recovery
window boundary (recovery is unambiguous only when the distance is strictly
less than half the window) is pinned by tests, including the case at exactly
half a window where recovery deliberately does not match.

## Scope

Implemented: variable-length integers, packet headers, packet numbers,
transport parameters, the common frames, and the stream/connection state
machines.

Not yet implemented: the TLS 1.3 handshake integration and AEAD/header
protection (RFC 9001), loss recovery and congestion control (RFC 9002), and
the live UDP I/O loop. The codecs expose the field boundaries these layers
build on.

# Usage

How to build `quic_vibe`, run its tests, and use the library.

## Toolchain

A Nix flake provides everything (`clang`, `just`, `lizard`):

```sh
nix develop
```

Without Nix, install `clang`, `just`, and `lizard` yourself; the build targets
`x86_64-linux` only.

## just targets

```sh
just build   # compile every domain freestanding into build/*.o
just test    # build and run the hosted test suite
just ccn     # fail if any function exceeds cyclomatic complexity 3
just check   # ccn + test (use this before committing)
```

- `just build` compiles every domain with `-ffreestanding -nostdlib`, which is
  what proves the library is libc-free. The result is a set of `.o` files plus
  a freestanding `_start`.
- `just test` rebuilds the same sources in a hosted configuration so they can
  be exercised with assertions. The test harness is a tiny assert macro
  (`tests/test.h`); each domain has one `*_test.c`, all driven by
  `tests/run.c`.

## Layout

```
src/
  sys/      x86_64 direct syscalls, freestanding entry, base types
  varint/   variable-length integer codec + TLV cursor helpers   (RFC 9000 §16)
  packet/   long/short header parse/build; packet number          (RFC 9000 §17,
            truncation and recovery                                A.2/A.3)
  tparam/   transport parameter TLV codec                          (RFC 9000 §18)
  frame/    PADDING/PING/CRYPTO/STREAM/CONNECTION_CLOSE/ACK/       (RFC 9000 §19)
            NEW_CONNECTION_ID codecs
  fsm/      shared table-driven finite state machine engine
  stream/   sending/receiving stream state machines               (RFC 9000 §3)
  conn/     handshake lifecycle + per-space packet numbers         (RFC 9000 §12)
  hash/     SHA-256 and HMAC-SHA-256                          (FIPS 180-4/198-1)
  hkdf/     HKDF and HKDF-Expand-Label                         (RFC 5869/8446)
  aes/      AES-128 block cipher (also AES-ECB)                    (FIPS 197)
  gcm/      AES-128-GCM AEAD                              (NIST SP 800-38D)
  chacha/   ChaCha20, Poly1305, ChaCha20-Poly1305 AEAD             (RFC 8439)
  hp/       AES header protection                              (RFC 9001 §5.4)
  protect/  packet protection pipeline (nonce, AEAD seal, HP)  (RFC 9001 §5.3)
  tls/      Initial keys, X25519, handshake codec, key schedule
            (RFC 9001 §5.2, RFC 7748, RFC 8446)
  net/      userspace IPv4/UDP + checksum + in-memory link  (RFC 791/768/1071)
  endpoint/ kernel-free end-to-end handshake driver
  recovery/ RTT estimation, PTO, sent-packet & loss detection      (RFC 9002)
  cc/       NewReno congestion control                            (RFC 9002 §7)
  flow/     flow-control accounting + stream reassembly      (RFC 9000 §2.2/4)
  io/       UDP sockets (direct syscalls) + retransmission queue
  util/     shared inline helpers (constant-time compare, scalars)
  error/    transport error codes and CRYPTO_ERROR mapping       (RFC 9000 §20)
  keyupdate/ 1-RTT key update state machine                     (RFC 9001 §6)
  path/     path validation and migration state              (RFC 9000 §8.2/9)
  closelife/ connection close lifecycle (idle/closing/draining) (RFC 9000 §10)
  version/  version numbers, version_information TP, negotiation
            (RFC 8999/9368/9369)
  datagram/ unreliable DATAGRAM frames and TP                    (RFC 9221)
  grease/   grease_quic_bit transport parameter                  (RFC 9287)
  h3/       HTTP/3 frame codec + control/SETTINGS/GOAWAY          (RFC 9114)
tests/      hosted assert-based test harness, one file per domain
```

Many frame, packet, and transport-parameter codecs live in additional files
under the existing `frame/`, `packet/`, and `tparam/` directories (e.g.
`frame/ack.c`, `frame/flowctl.c`, `packet/retry.c`, `tparam/tpblob.c`).

Each domain is a directory with a `.h` (types, constants, prototypes) and a
`.c` (implementation). Include the header you need, e.g. `#include
"varint/varint.h"`, and link the matching `.o` from `just build`.

## Using the library

The pieces compose bottom-up. A few representative entry points:

- **Codecs** return the number of bytes written/consumed, or `0` on
  overflow/truncation — e.g. `quic_varint_encode`, `quic_frame_put_stream`,
  `quic_ack_encode`.
- **AEAD** seals/opens in place and rejects tampering:
  `quic_gcm_seal`/`quic_gcm_open`, `quic_chapoly_seal`/`quic_chapoly_open`.
  `open` leaves the plaintext buffer untouched on authentication failure.
- **Packet protection** ties the layers together:
  `quic_protect_seal` builds the nonce (`iv XOR pn`), AEAD-seals the payload
  with the header as AAD, then applies header protection; `quic_protect_open`
  reverses it.
- **Key derivation**: `quic_initial_derive` for Initial keys (RFC 9001
  Appendix A), `quic_x25519`/`quic_x25519_base` for ECDHE, and
  `quic_tls_handshake_secret`/`quic_tls_handshake_keys` for the schedule.

### End to end, without the kernel

`endpoint/` drives a complete handshake with no sockets and no kernel network
stack. The client builds a ClientHello, frames it as CRYPTO, protects it as an
Initial packet, wraps it in UDP/IPv4, and pushes it onto an in-memory link
(`net/memlink`); the server reads it back with zero syscalls, recovers the
X25519 share, and both sides run ECDHE and the TLS key schedule to the same
handshake keys. A 1-RTT STREAM then round-trips under those keys.

The data path makes no `socket`/`sendto`/`recvfrom` calls — sockets live only
in an optional `io/udp` that the end-to-end path does not use. See
`tests/endpoint_test.c` for the full worked flow.

## Correctness

Every codec is checked against official test vectors and has round-trip and
truncated-input tests:

- Transport codecs against the RFC 9000 Appendix A sample vectors. The
  packet-number recovery window boundary is pinned, including the case at
  exactly half a window where recovery deliberately does not match.
- Cryptography against the published vectors for each primitive: SHA-256
  (NIST), HMAC (RFC 4231), HKDF (RFC 5869), AES-128 (FIPS 197), AES-GCM
  (NIST SP 800-38D), ChaCha20/Poly1305 (RFC 8439), X25519 (RFC 7748). The
  AEADs reject tampered ciphertext, AAD, or tags.
- The RFC 9001 Appendix A Initial keys and the §5.4.2 header-protection mask
  match byte for byte, exercising the whole HKDF → AEAD → header-protection
  stack together.
- Recovery and congestion control against the RFC 9002 formulas, with the
  packet-loss threshold boundary and the `cwnd >= kMinimumWindow` floor pinned.
- The IPv4/UDP stack against the RFC 1071 checksum example, with build/verify
  round-trips and a full datagram carried across the in-memory link.

## Scope

Implemented end to end: the transport wire format and the complete frame set
(including ACK with ECN, RESET_STREAM/STOP_SENDING, the flow-control and
*_BLOCKED frames, NEW_TOKEN, RETIRE_CONNECTION_ID, PATH_CHALLENGE/RESPONSE,
HANDSHAKE_DONE, and a frame-type classifier); short-header build, Retry, and
Version Negotiation packets; the full transport-parameter set; transport
error codes; stream/connection state machines; the full cryptography stack
with RFC 9001 Initial/handshake key derivation and the Retry Integrity Tag;
the packet protection pipeline; loss recovery and congestion control; flow
control and reassembly; a userspace IPv4/UDP stack over an in-memory link;
and a kernel-free endpoint that establishes a handshake and exchanges 1-RTT
data.

Also implemented, each verified against its RFC: the 1-RTT key update, path
validation and migration, the connection close lifecycle, version
negotiation with downgrade protection and QUIC v2, the unreliable DATAGRAM
extension (RFC 9221), grease_quic_bit (RFC 9287), and the HTTP/3 frame codec
with the control-stream / SETTINGS / GOAWAY state machine (RFC 9114).

Not implemented: QPACK header compression (RFC 9204), full TLS 1.3
certificate/signature verification, and 0-RTT. The HTTP/3 HEADERS payload is
passed through opaque, and the endpoint proves transport key agreement and
encrypted data exchange rather than full PKI authentication.

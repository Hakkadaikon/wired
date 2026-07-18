[Docs](../README.md) › Architecture › Overview

# Architecture and Data Flow

> **TL;DR** — the kernel only moves already-encrypted UDP bytes. Everything
> QUIC-related — packets, keys, retransmission, HTTP/3 — happens in five
> user-space layers inside this SDK.

## The boundary between user space and the kernel

In TCP, the kernel owns retransmission, ordering, congestion control, and all of the connection state.
QUIC removed that constraint by standing on top of UDP: because UDP only carries datagrams — no reliability, no ordering, no encryption — all of those concerns can be pulled into the application.
wired pushes this to the limit and shows the kernel nothing of QUIC's semantics.

```text
            user space (wired)
 ┌────────────────────────────────────────────┐
 │  app        HTTP/3 · QPACK · WebTransport  │
 │  tls        TLS 1.3 handshake · keys       │
 │  transport  packets · loss recovery ·      │
 │             streams · UDP/XDP I/O          │
 │  crypto     AEAD · signatures · X.509      │
 │  common     varint · cursor · syscalls     │
 └─────────────────────┬──────────────────────┘
                       │  raw encrypted UDP bytes
 ┌─────────────────────▼──────────────────────┐
 │  kernel   socket · bind · sendto ·         │
 │           recvfrom · poll · getrandom      │
 └────────────────────────────────────────────┘
```

The place that actually issues a syscall is concentrated in a single inline-assembly function called `syscall6`; every other piece of C code reaches the kernel only through that function, the sole exceptions being three unavoidable asm trampolines (thread exit, signal return, and the `_start` entry stub).
The wire loop needs only a small set: UDP send/receive, socket setup and `poll`, and `getrandom`.
The complete list, with why each syscall is needed and where it is issued, is in [Syscalls](../syscalls.md).

Everything else — packet framing, encryption and header protection, the TLS handshake, loss recovery, congestion control, stream multiplexing, HTTP/3 and QPACK, X.509 verification, every cryptographic function — is held in user space.
The test path that merely round-trips bytes through memory (memlink, an in-memory loopback transport under `src/transport/io/socket/net/`) never issues a single syscall at all.

This is what makes the libc-free design verifiable: compiling under `-ffreestanding -nostdlib` proves the absence of external dependencies, and with the kernel contact closed to one wrapper function, every other line can be treated as a pure transformation.

## The five layers

| Layer | Directory | Responsibility |
|----|------------|------|
| app | `src/app/` | HTTP/3 frames and state machine, header compression with QPACK. |
| tls | `src/tls/` | TLS 1.3 handshake, key schedule, transport parameters. |
| transport | `src/transport/` | Packet framing and protection, loss recovery, congestion control, streams, UDP I/O. |
| crypto | `src/crypto/` | AEAD, hashing, signatures, key derivation, X.509 parsing and verification. |
| common | `src/common/` | varint, byte cursor, syscall wrapper, randomness, error codes. |

Dependencies point downward, with one deliberate exception at the QUIC⇄TLS
integration point (every layer also uses common, omitted for clarity):

```text
  app ──► transport ──► crypto ──► common
              ╎              ▲
              ╎ (exception)  │
              └╌╌╌╌► tls ────┘
```

The exception exists because the QUIC handshake carries TLS messages inside CRYPTO frames, transported in QUIC packets: transport must drive the TLS handshake, and crypto's key derivation shares the Initial-key type with tls.
The keys are made by tls, but the bytes those keys protect are carried by transport — the two need each other, and forcing the dependency fully downward would split that integration unnaturally.

common is the complete bottom layer that depends on nothing.
All layers share its varint encoding and byte cursor, and shared small helpers live here as `inline` to avoid symbol collisions in the single-translation-unit test build.

## Data flow

Three representative flows. In each, the order is forced by a dependency, noted after the steps.

### Sending: from GET to the wire

1. HTTP/3 compresses the request headers with QPACK and wraps the frames into QUIC STREAM frames.
2. transport finalizes the packet header.
3. crypto seals the payload with AEAD, using that header as the additional authenticated data (AAD).
4. transport builds a mask from a sample of the ciphertext and applies header protection over fields like the packet number.
5. Multiple packets are coalesced into one datagram and handed to `sendto`.

The order cannot be rearranged: AEAD needs the finalized header (step 2 before 3), and header protection needs AEAD's ciphertext (step 3 before 4).

### Receiving: from the wire to the application

1. `recvfrom` delivers one datagram; transport splits any coalesced packets.
2. transport removes header protection, exposing the packet number.
3. The packet number fixes the AEAD nonce; crypto decrypts.
4. transport parses the frames and reassembles STREAM data.
5. The reassembled bytes flow up to HTTP/3 / QPACK.

Again the order is forced: the packet number is under header protection (step 2 before 3), and the nonce needs the packet number (step 3 before 4).

### The handshake: establishing the connection while making the keys

1. Client sends ClientHello in an Initial packet — Initial keys are derived from the destination connection ID by a fixed public procedure, so even the first packet is structurally protected (though not secret).
2. Server answers with ServerHello (`key_share`); the ECDHE shared secret is now fixed and both sides derive the Handshake keys.
3. Server sends EncryptedExtensions / Certificate / CertificateVerify / Finished; the client verifies the certificate signature, authenticating the peer.
4. Client sends Finished; both sides derive the 1-RTT keys for application data.
5. Server sends HANDSHAKE_DONE; the connection is CONFIRMED and the Handshake keys are discarded.

The handshake dissolves its own bootstrap problem — nothing can be encrypted without a key — by producing the keys as it goes.

---

**Next:** [The Layers](layers.md) — each layer in depth.
([all docs](../README.md))

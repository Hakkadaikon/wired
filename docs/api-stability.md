# API Stability

Which functions in the public headers are the stable application-facing
surface, and which are low-level internals that happen to be reachable from
the same headers. This is a map, not a tutorial — see
`docs/getting-started.md` for how to use the library.

## Why the line matters

`src/wired.h` is a single include that pulls in seventeen headers. Some of
those expose one top-level entry point meant to be called once; others expose
an internal state machine's individual steps, callable in the wrong order or
with a dangling buffer if the caller does not already understand the
underlying protocol. Both kinds carry a non-`static` `wired_`/`quic_` name and
both compile the same way, so the header alone does not tell you which is
which. This document does.

One stable entry point is NOT in `wired.h`: the driver front end lives in
`src/app/http3/server/srvdriver/srvdriver.h`, which a caller includes
separately.

## Stable API (application-facing, breaking changes avoided)

Call these without needing to know the QUIC/TLS state machine underneath.

| Function | Role |
|---|---|
| `wired_srvdriver_parse`, `wired_srvdriver_run` | The recommended entry point: parse `--port`/`--workers`/`--ifindex`/`--cores`/`--pin-core` from argv and dispatch to one of the four server drivers (single-process, forked workers, AF_XDP, threads). Not pulled in by `wired.h` — include `srvdriver.h` yourself. |
| `wired_server_run` | Run a complete single-process server: bind, accept, and serve requests until killed. |
| `wired_server_run_opt` | Same, plus opt-in knobs (busy-poll, AF_XDP driver, WebTransport callbacks). `opt` must not be 0; all-default knobs make it byte-identical to `wired_server_run`. |
| `wired_server_broadcast_datagram` | Queue a QUIC DATAGRAM to every connection with an active WebTransport session. Callable only from inside the server's own loop (i.e. from a callback); neither thread- nor signal-safe. |
| `wired_srvrun_handler` (struct) | The callback + context pair passed to the run functions to answer requests. |
| `wired_certreload_load`, `wired_certreload_load_or_selfsigned` | Load a cert chain + P-256 key from a PEM pair into caller-owned storage; the store must outlive the identity built from it. `_or_selfsigned` keeps the existing identity when no cert path is set, and dies with a diagnostic when a set path fails to load. |
| `wired_udp_socket`, `wired_udp_bind`, `wired_udp_send`, `wired_udp_recv`, `wired_udp_recvfrom`, `wired_udp_close`, `wired_udp_addr` | Plain UDP socket calls, no QUIC state involved. Safe to call in any order a normal sockets program would. |
| `wired_pem_next` | Decode one PEM block from text; repeat the call to walk a fullchain file. Self-contained, no ordering constraints beyond the cursor argument. |
| `wired_eckey_p256_priv` | Extract a P-256 private scalar from DER (SEC1 or PKCS#8). Pure decode, no state. |
| `wired_fio_read`, `wired_fio_append` | Whole-file read / append via raw syscalls. Pure I/O, no protocol state. |
| `wired_header_parse`, `wired_header_build_long` | Parse/build the invariant part of a QUIC packet header. Pure codec: given bytes in, bytes or fields out. |
| `wired_log_str`, `wired_log_ts`, `wired_fmt_u64`, `WIRED_LOG` | Optional tracing output. Stateless, side-effect-only (stderr), safe to call anywhere. |

These are grouped as stable because each is either a single top-level
operation (the run/driver functions) or a pure function with no cross-call
invariants (codecs, file I/O, logging). Their signatures are the ones an
application author writes against directly, per `docs/getting-started.md`.

## Low-level / internal API (use with care)

These are reachable from the public headers because the app-facing layer is
built out of them, not because they are meant to be called directly by most
users. Each has a call-order or lifetime precondition that is easy to violate.

| Function | Why it needs care |
|---|---|
| `wired_srvboot_is_initial`, `wired_srvboot_accept` | Cold-starts one connection from a raw Initial datagram. `accept` must run before any `wired_srvloop_step` call for that connection, and its `wired_srvboot_id` fields are views the caller must keep alive for the call. |
| `wired_srvloop_init`, `wired_srvloop_set_handler`, `wired_srvloop_step` | Drives one connection's per-datagram state machine. `init` must run once per connection before `step`; `step` must be called in datagram-arrival order; the decoded request in `wired_srvloop` is only valid until the next `step`. |
| `wired_srvloop_send_initial`, `wired_srvloop_send_handshake`, `wired_srvloop_send_onertt` | Seal one specific packet type under a specific key level. Calling the wrong one for the current handshake phase (e.g. `send_handshake` before the Handshake key is derived) fails or produces an unusable packet. |
| `wired_server_init`, `wired_server_set_cids`, `wired_server_recv_initial`, `wired_server_build_flight`, `wired_server_feed`, `wired_server_handshake_done`, `wired_server_is_confirmed`, `wired_server_listen`, `wired_server_pump`, `wired_server_run_handshake`, `wired_server_close` | The server-side handshake orchestrator's individual phase transitions (`INITIAL -> CH_RECVD -> FLIGHT_SENT -> CONFIRMED`). Each function is only valid in specific phases (e.g. `set_cids` must run before `build_flight`); calling out of order is a documented failure mode, not a crash-safe no-op. `wired_server_run` wraps all of these for the common case. |
| `wired_srvrun_env_size`, `wired_srvrun_env_init`, `wired_srvrun_serve_env` | Caller-owned extra loop instances (e.g. one per thread): allocate `env_size()` bytes and `env_init` them before the first `serve_env`, and set `no_signal_handlers=1` on every instance but one — SIGTERM/SIGHUP handlers are process-wide. |
| `wired_srvrun_shutdown_word` | Pointer to the process-wide graceful-shutdown word, 0 until shutdown then monotonically 1; every loop in the process polls the same word, so setting it stops them all. |
| `wired_srvrun_broadcast_register`, `wired_srvrun_broadcast_unregister` | Registers the calling thread into the fixed 16-slot broadcast mesh; the passed `inbox_row` and `env` must stay live and unmoved until `unregister`, which must run before the thread exits. |
| `wired_srvworkers_run` | Forks N shared-nothing worker processes and becomes their restart supervisor — it does not return in normal operation (negative only if the very first `fork` fails). |
| `wired_srvthreads_run`, `wired_srvthreads_parse_cores` | Thread fan-out: the control thread alone owns the signal handlers and (in XDP mode) the shared BPF object, and joins every worker before releasing them. `parse_cores` rejects an empty list or empty field instead of running zero workers. |
| `wired_srvxdp_open`, `wired_srvxdp_open_shared`, `wired_srvxdp_rx_burst`, `wired_srvxdp_send`, `wired_srvxdp_close`, `wired_srvxdp_print_stats` | AF_XDP driver instance. The kernel allows one XDP link per interface, so multi-queue setups must use `open_shared` against a caller-owned `wired_srvxdpbpf` instead of a second `open`; `send` drops (returns 0, relying on QUIC retransmission) until the peer's MAC is learned from RX. |
| `wired_srvxdpbpf_open`, `wired_srvxdpbpf_register`, `wired_srvxdpbpf_close` | The shared per-interface BPF map/program/link. Open it once per interface, register each queue's socket into it, and keep it open for as long as any registered socket is in use — closing early orphans them. |
| `wired_wt_session_init`, `wired_wt_session_establish`, `wired_wt_session_drain`, `wired_wt_session_close`, `wired_wt_session_offer_stream`, `wired_wt_session_offer_datagram` | The WebTransport session lifecycle (`unestablished -> established -> draining -> closed`, closed absorbing): transitions out of order are rejected no-ops. A 0 from `offer_stream` obliges the caller to reset the stream with `WT_BUFFERED_STREAM_REJECTED`; a 0 from `offer_datagram` is a sanctioned drop needing no action. |
| `wired_h3reqdrive_send_get`, `wired_h3reqdrive_send_method`, `wired_h3reqdrive_recv_get` | HTTP/3 request codecs. `recv_get`'s recovered pseudo-headers are views into the caller's scratch buffer and the stream data, both of which must stay alive for as long as the parsed request is used. |
| `quic_x25519`, `quic_x25519_base` | Raw Curve25519 scalar multiplication. The caller MUST reject an all-zero `quic_x25519` result (RFC 7748 6.1); skipping that check silently accepts a non-contributory (low-order) key exchange. |
| `quic_put_bytes`, `quic_take_bytes` | Cursor-based byte copy used by codec internals. Correct only when the caller manages the cursor (`*off`) consistently across calls; no bounds memory beyond what is passed in. |
| `quic_memcpy`, `quic_memset` | Not meant to be called by application code at all — they exist only so a freestanding (`-nostdlib`) binary that defines `WIRED_MAIN` can supply the libc-named `memcpy`/`memset` symbols the compiler emits implicitly. An implementation detail of the freestanding build, exposed because that shim has to live somewhere. |

## Versioning policy

The project has no released version number yet, so this is a proposed
default, not a retrofit of existing practice.

- **Stable API**: breaking changes (signature change, removal, semantic
  change to pre/postconditions) are reserved for a major version bump.
  Additive changes (new function, new optional field with a safe default)
  are a minor bump.
- **Low-level/internal API**: may change signature, calling convention, or
  preconditions in a minor version. These functions exist to let
  `wired_server_run` and the example programs be built at all; they are not
  a contract with external callers. Treat them like
  `docs/getting-started.md`'s worked examples — read the current header
  before depending on one.
- Patch versions are bug fixes only, in both layers, with no signature
  change.

Until a version number exists, treat every commit to a low-level function as
a potential behavior change and every commit to a stable function as
requiring a changelog note.

## Known naming deviations

Per `.claude/rules/naming-and-unity-build.md`, the app-facing layer (server,
srvloop, h3srv, h3reqdrive, udp, header, srvboot, srvrun, pem, eckey, fio)
carries the `wired_<domain>_` prefix; everything else in the SDK core carries
`quic_<domain>_`.

- `common/platform/debug/debug.h` uses the `wired_` prefix
  (`wired_fmt_u64`, `wired_log_str`, `wired_log_ts`) and the `WIRED_DEBUG_H`
  include guard, but `debug` is not listed among the app-facing domains in
  the naming rule. `common/platform/cliargs/cliargs.h` (`wired_cliargs_*`)
  is in the same position. This is a documentation gap in the naming rule,
  not a code change — recorded here, not fixed in code per the task scope.
- The naming rule's app-facing domain list predates the newer app-facing
  domains (certreload, mimetype, staticfile, srvdriver, srvworkers,
  srvthreads, srvxdp, srvxdpbpf, and the WebTransport session layer), all of
  which carry `wired_` consistently with the rule's intent. Same gap
  category: the list is stale, the prefixes are not.

No prefix inconsistency was found: every function checked in the seventeen
headers `wired.h` includes (plus `srvdriver.h`) uses either `wired_` or
`quic_` as its layer prescribes.

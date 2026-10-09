[Docs](README.md) › API Stability

# API Stability

> **Most applications need five things:** `wired_srvdriver_parse` +
> `wired_srvdriver_run` (parse flags, serve), a `wired_srvrun_handler`
> (your callback), and `wired_certreload_load_or_selfsigned` (real certs).
> WebTransport apps add `wired_server_broadcast_datagram`. Everything else
> on this page is for going further.

> **Rule of thumb** — if a function is in the *Stable API* table below, call
> it freely; it either does one whole job or is a pure function with no
> hidden ordering rules. Anything in the *Low-level* table has call-order or
> lifetime preconditions: read its header comment before using it.

Which functions in the public headers are the stable application-facing
surface, and which are low-level internals that happen to be reachable from
the same headers. This is a map, not a tutorial — see
`docs/getting-started.md` for how to use the library.

## Why the line matters

`src/wired.h` is a single include that pulls in every public header. Some of
those expose one top-level entry point meant to be called once; others expose
an internal state machine's individual steps, callable in the wrong order or
with a dangling buffer if the caller does not already understand the
underlying protocol. The prefix tells you the audience — `wired_*` is the
application-facing surface, a bare module token (`sdrv_*`, `moqctl_*`,
`bytes_*`) is SDK-internal — but within `wired_*` it does not tell you which
functions are the whole-job entry points and which are low-level steps with
ordering preconditions. This document does.

Everything below is reachable from the single `wired.h` include — no second
header is needed.

## Stable API (application-facing, breaking changes avoided)

Call these without needing to know the QUIC/TLS state machine underneath.

| Function | Role |
|---|---|
| `wired_srvdriver_parse`, `wired_srvdriver_run` | The recommended entry point: parse `--port`/`--workers`/`--ifindex`/`--cores`/`--pin-core` from argv and dispatch to one of the four server drivers (single-process, forked workers, AF_XDP, threads). |
| `wired_server_run` | Run a complete single-process server: bind, accept, and serve requests until killed. |
| `wired_server_run_opt` | Same, plus opt-in knobs (busy-poll, AF_XDP driver, WebTransport callbacks, the per-loop-step `wired_srvrun_opt.on_step` callback, and -- a minor addition -- the WebTransport Origin verdict `wired_srvrun_opt.wt_origin_check`, which gets an empty `origin` span when the CONNECT carries no origin header; and -- also minor -- `wired_srvrun_opt.wt_on_session_draining`, called when the peer sends WT_DRAIN_SESSION on a session's CONNECT stream). `opt` must not be 0; all-default knobs make it byte-identical to `wired_server_run`. |
| `wired_server_broadcast_datagram` | Queue a QUIC DATAGRAM to every connection with an active WebTransport session. Callable only from inside the server's own loop (i.e. from a callback); neither thread- nor signal-safe. |
| `wired_server_wt_open_uni`, `wired_server_wt_open_bidi`, `wired_server_wt_stream_reply` | Open a server-initiated WebTransport uni/bidi stream (payload must carry the WT stream-signal prefix), or reply on a client-opened bidi stream. Same loop-context constraint as `broadcast_datagram`; the SDK holds `payload` as a view, so it must stay alive until fully acknowledged. |
| `wired_server_wt_stream_inflight` | 1 while a server-sent stream's send slot still holds `stream_id` (bytes not yet fully acknowledged, or the stream still open for appends), 0 once the slot was reaped or `stream_id` never named a server-sent stream on this session — the signal that a view payload handed to the open calls above may be reused. Same loop-context constraint. |
| `wired_server_wt_drain_session` | Minor addition: send WT_DRAIN_SESSION on a session's CONNECT stream on the loop's next step, at most once per session (a repeat call returns 1 without sending); 0 when the session is no longer live. Same loop-context constraint. |
| `wired_server_wt_stream_priority` | Minor addition: set a server-sent stream's RFC 9218 urgency (0..7, lower first, default 3). Each send pass serves only the most urgent streams that can send; equal urgency keeps the existing turn order. Negative for urgency above 7 or an id with no open send slot. Same loop-context constraint. |
| `wired_server_wt_occupancy`, `wired_wt_occupancy` (struct) | Minor addition: the calling loop's open WebTransport sessions and client-opened WT streams, with their compile-time capacities, for stats. A point-in-time snapshot, unlike the cumulative totals of `wired_srvrun_env_wt_usage`. Same loop-context constraint. |
| `wired_srvrun_handler` (struct) | The callback + context pair passed to the run functions to answer requests. Minor additions: its trailing `http` member (0 = unused) takes a `wired_http_handler`, which fills a `wired_http_exchange` to choose the status and add up to `WIRED_HTTP_MAX_FIELDS` `wired_http_field` response headers. `wired_http_field` is a typedef of the internal `qpack_field` (two `wired_span`s, name then value), so its layout follows that struct. Its trailing `on_body` member (0 = buffer the body whole) takes a `wired_srvloop_on_body`, which receives the request body in chunks as it streams in before the responder runs. |
| `wired_http_req_header` | Minor addition: look up a regular request header of `wired_http_exchange.req` by its lowercase name (exact match). `cookie` returns all crumbs joined with `; `; other duplicates return the first. Apart from cookie, origin and wt-available-protocols, only the first `WIRED_H3REQDRIVE_MAX_HDRS` (32) regular headers are kept; later ones are not found. In later rounds of a streaming response the request is a copy with 512 bytes of room for its views and headers, so trailing headers that do not fit are not found there. The value view lives as long as the request's other views. |
| `wired_certreload_load`, `wired_certreload_load_or_selfsigned` | Load a cert chain + P-256 key from a PEM pair into caller-owned storage; the store must outlive the identity built from it. `_or_selfsigned` keeps the existing identity when no cert path is set, and dies with a diagnostic when a set path fails to load. |
| `wired_udp_socket`, `wired_udp_bind`, `wired_udp_send`, `wired_udp_recv`, `wired_udp_recvfrom`, `wired_udp_close`, `wired_udp_addr` | Plain UDP socket calls, no QUIC state involved. Safe to call in any order a normal sockets program would. |
| `wired_pem_next` | Decode one PEM block from text; repeat the call to walk a fullchain file. Self-contained, no ordering constraints beyond the cursor argument. |
| `wired_eckey_p256_priv` | Extract a P-256 private scalar from DER (SEC1 or PKCS#8). Pure decode, no state. |
| `wired_fio_read`, `wired_fio_append`, `wired_fio_write_new`, `wired_fio_mkdir` | Whole-file read / append / truncate-and-replace, and directory creation, via raw syscalls. Pure I/O, no protocol state. |
| `wired_fio_open`, `wired_fio_size`, `wired_fio_pread`, `wired_fio_close` | Chunked file access: open read-only, stat the size, read at an offset, close — how the examples stream a large static file without loading it whole. Plain fd discipline, no protocol state. |
| `wired_header_parse`, `wired_header_build_long` | Parse/build the invariant part of a QUIC packet header. Pure codec: given bytes in, bytes or fields out. |
| `wired_log_str`, `wired_log_ts`, `wired_fmt_u64`, `WIRED_LOG` | Optional tracing output. Stateless, side-effect-only (stderr), safe to call anywhere. |
| `wired_snprintf`, `wired_vsnprintf`, `wired_dprintf` | libc-free printf-compatible formatter (%d %i %u %x %X %p %s %c %% %f, flags, width, precision, length modifiers). Pure formatting; `wired_dprintf` only calls write(2). Deviations from C99 are listed in `common/fmt/fmt.h`. |
| `wired_obuf_printf` | printf-append into a `wired_obuf` at `len` (e.g. an HTTP response body); at most `cap - len - 1` bytes, returns the bytes appended. |
| `wired_span_eq`, `wired_span_eq_cstr`, `wired_span_cstr`, `wired_span_to_cstr`, `WIRED_SPAN_ARG` (`common/bytes/text/text.h`) | Byte-view helpers: compare two views / a view with a C string (not constant-time), view of a C string, copy a view out NUL-terminated (truncating), and `"%.*s"` arguments for a view. |
| `wired_hex_encode`, `wired_dump_hex`, `wired_dump_text` (`common/bytes/text/text.h`) | Lowercase hex of a view into a buffer, or straight to an fd; write a view's bytes to an fd as text. |
| `wired_h3req_path` | The request's `:path` as one `wired_span`. |
| `wired_http_reply_text`, `wired_http_add_field` (`srvrun/httpx.h`) | Fill a `wired_http_exchange`: status + text/plain + body text in one call; append a response header field from two C strings (0 when the field table is full). |
| `wired_fio_read_span` | `wired_fio_read` returning the contents as a `wired_span` (n = 0 on error). |
| `wired_span_find` | Index of the first given byte in a view, -1 if absent. |
| `wired_cstr_eq`, `wired_cstr_append`, `wired_span_strip_lead`, `wired_obuf_put` (`common/bytes/text/text.h`) | C-string equality; append a view to a NUL-terminated buffer (cut at cap - 1); a view without one leading byte; append raw bytes to a `wired_obuf` (cut at cap). |
| `wired_srvboot_demo`, `wired_srvboot_demo_keys` (`srvboot/srvdemo.h`) | Fixed, deterministic demo identity (counting-pattern keys, self-signed certificate) for samples and tests. Never for production. |
| `wired_srvboot_cert_sha256`, `wired_srvboot_log_fingerprint` (`srvboot/srvdemo.h`) | SHA-256 of the leaf certificate an identity presents (the browser `serverCertificateHashes` value), raw or logged colon-separated. Not reentrant (process-wide scratch server). |

These are grouped as stable because each is either a single top-level
operation (the run/driver functions) or a pure function with no cross-call
invariants (codecs, file I/O, logging). Their signatures are the ones an
application author writes against directly, per `docs/getting-started.md`.

## Low-level / internal API (use with care)

These are reachable from the public headers because the app-facing layer is
built out of them, not because they are meant to be called directly by most
users. Each has a call-order or lifetime precondition that is easy to violate.

<details>
<summary>The full low-level list</summary>

| Function | Why it needs care |
|---|---|
| `wired_srvboot_is_initial`, `wired_srvboot_accept` | Cold-starts one connection from a raw Initial datagram. `accept` must run before any `wired_srvloop_step` call for that connection, and its `wired_srvboot_id` fields are views the caller must keep alive for the call. |
| `wired_srvloop_init`, `wired_srvloop_set_handler`, `wired_srvloop_step`, `wired_srvloop_wt_refuse` | Drives one connection's per-datagram state machine. `init` must run once per connection before `step`; `step` must be called in datagram-arrival order; the decoded request in `wired_srvloop` is only valid until the next `step`. `wt_refuse` (minor addition) queues a WebTransport stream the slot table could not take, for the run loop to reset with H3_REQUEST_REJECTED. |
| `wired_srvloop_send_initial`, `wired_srvloop_send_handshake`, `wired_srvloop_send_onertt` | Seal one specific packet type under a specific key level. Calling the wrong one for the current handshake phase (e.g. `send_handshake` before the Handshake key is derived) fails or produces an unusable packet. |
| `wired_server_init`, `wired_server_set_cids`, `wired_server_recv_initial`, `wired_server_build_flight`, `wired_server_feed`, `wired_server_handshake_done`, `wired_server_is_confirmed`, `wired_server_listen`, `wired_server_pump`, `wired_server_run_handshake`, `wired_server_close` | The server-side handshake orchestrator's individual phase transitions (`INITIAL -> CH_RECVD -> FLIGHT_SENT -> CONFIRMED`). Each function is only valid in specific phases (e.g. `set_cids` must run before `build_flight`); calling out of order is a documented failure mode, not a crash-safe no-op. `wired_server_run` wraps all of these for the common case. |
| `wired_srvrun_env_size`, `wired_srvrun_env_init`, `wired_srvrun_serve_env` | Caller-owned extra loop instances (e.g. one per thread): allocate `env_size()` bytes and `env_init` them before the first `serve_env`, and set `no_signal_handlers=1` on every instance but one — SIGTERM/SIGHUP handlers are process-wide. |
| `wired_srvrun_shutdown_word` | Pointer to the process-wide graceful-shutdown word, 0 until shutdown then monotonically 1; every loop in the process polls the same word, so setting it stops them all. |
| `wired_srvrun_broadcast_register`, `wired_srvrun_broadcast_unregister` | Registers the calling thread into the fixed 16-slot broadcast mesh; the passed `inbox_row` and `env` must stay live and unmoved until `unregister`, which must run before the thread exits. |
| `wired_srvworkers_run` | Forks N shared-nothing worker processes and becomes their restart supervisor (a crashed worker is respawned, an exit-0 worker is not). SIGTERM is forwarded once to every worker; it returns 0 once every worker is reaped, negative if the initial `fork` fails. |
| `wired_srvthreads_run`, `wired_srvthreads_parse_cores` | Thread fan-out: the control thread alone owns the signal handlers and (in XDP mode) the shared BPF object, and joins every worker before releasing them. `parse_cores` rejects an empty list or empty field instead of running zero workers. |
| `wired_srvxdp_open`, `wired_srvxdp_open_shared`, `wired_srvxdp_rx_burst`, `wired_srvxdp_send`, `wired_srvxdp_close`, `wired_srvxdp_print_stats` | AF_XDP driver instance. The kernel allows one XDP link per interface, so multi-queue setups must use `open_shared` against a caller-owned `wired_srvxdpbpf` instead of a second `open`; `send` drops (returns 0, relying on QUIC retransmission) until the peer's MAC is learned from RX. |
| `wired_srvxdpbpf_open`, `wired_srvxdpbpf_register`, `wired_srvxdpbpf_close` | The shared per-interface BPF map/program/link. Open it once per interface, register each queue's socket into it, and keep it open for as long as any registered socket is in use — closing early orphans them. |
| `wired_wt_session_init`, `wired_wt_session_establish`, `wired_wt_session_drain`, `wired_wt_session_close`, `wired_wt_session_offer_stream`, `wired_wt_session_offer_datagram` | The WebTransport session lifecycle (`unestablished -> established -> draining -> closed`, closed absorbing): transitions out of order are rejected no-ops. A 0 from `offer_stream` obliges the caller to reset the stream with `WT_BUFFERED_STREAM_REJECTED`; a 0 from `offer_datagram` is a sanctioned drop needing no action. |
| `wired_h3reqdrive_send_get`, `wired_h3reqdrive_send_method`, `wired_h3reqdrive_recv_get` | HTTP/3 request codecs. `recv_get`'s recovered pseudo-headers are views into the caller's scratch buffer and the stream data, both of which must stay alive for as long as the parsed request is used. |
| `wired_x25519`, `wired_x25519_base` | Raw Curve25519 scalar multiplication. The caller MUST reject an all-zero `wired_x25519` result (RFC 7748 6.1); skipping that check silently accepts a non-contributory (low-order) key exchange. |
| `bytes_put`, `bytes_take` | Cursor-based byte copy used by codec internals. Correct only when the caller manages the cursor (`*off`) consistently across calls; no bounds memory beyond what is passed in. |
| `bytes_memcpy`, `bytes_memset` | Not meant to be called by application code at all — they exist only so a freestanding (`-nostdlib`) binary that defines `WIRED_MAIN` can supply the libc-named `memcpy`/`memset` symbols the compiler emits implicitly. An implementation detail of the freestanding build, exposed because that shim has to live somewhere. |

</details>

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

## The naming rule

Per `.claude/rules/naming-and-unity-build.md`, the prefix encodes the
audience, not the protocol:

- **`wired_*` / `WIRED_*`** — the application-facing surface: everything in
  the Stable table, plus the low-level helpers the bundled examples call
  (the span types and codecs above). Breaking-change policy per the
  versioning section.
- **module token (`sdrv_*`, `h3_*`, `bn_*`, `LEVEL_*`)** — SDK-internal,
  non-`static` names shared between modules. No stability promise.
- **`static` helpers** — file-local, prefixed enough to stay unique in the
  unity build.

A handful of internal helpers (`bytes_put`, `bytes_memcpy`, `wired_x25519`)
are reachable from `wired.h` because the app-facing layer is built out of
them; the Low-level table above is the authoritative list of what needs
care.

## MOQT is not on this map

`src/app/moqt/` (twelve modules: `cache`, `ctl`, `data`, `dgram`, `fetch`,
`kvp`, `ns`, `run`, `sess`, `tstat`, `ver`, `vi`) implements MOQT — a session
negotiates whichever of draft-ietf-moq-transport-18/19/22 the peer's WT
subprotocol offers (`moqt-18`/`moqt-19`/`moqt-22`) — but its headers are not
included by `src/wired.h`, so none of it appears in either table above —
`wired_moqt_init` and friends (`run/moqtrun.h`) are deliberately outside the
one-include surface this document maps. This is a design choice, not an
oversight: `examples/moqt_chat` includes `app/moqt/run/moqtrun.h` directly
alongside `wired.h`, the same way any other MOQT application would. Treat
`src/app/moqt/` headers with the same care as the Low-level table — read the
header before calling.

Minor additions to `run/moqtrun.h` in this round, all zero = old behavior:

| Name | Role |
|---|---|
| `wired_moqt_cache_attach` | Hand the hub a caller-owned arena for its whole-group object cache, which serves FETCH; without it FETCH reports every range as unknown. |
| `wired_moqt_goaway` | Send MOQT GOAWAY (optional New Session URI, timeout) on every session, then PUBLISH_DONE and close with GOAWAY_TIMEOUT once the timeout passes. |
| `wired_moqt_on_session_draining` | Shaped as `wired_srvrun_opt.wt_on_session_draining`: a peer's WT_DRAIN_SESSION starts the GOAWAY sequence for that session. |
| `wired_moqt_on_stream_reset` | Tell the hub a peer reset one of its streams, which cancels the request or FETCH that stream carried. |
| `wired_moqt_hub.authorize_namespace`, `authorize_ns_ctx`, `wired_moqt_authorize_ns_fn` | Optional authorizer for PUBLISH_NAMESPACE / SUBSCRIBE_NAMESPACE; 0 grants all. |
| `wired_moqt_hub.authorize_publish`, `authorize_pub_ctx` | Optional authorizer for PUBLISH (a `wired_moqt_authorize_fn`, shown the Full Track Name and token): a relay's impersonation check, the same MUST in every draft; 0 grants all. |
| `wired_moqt_io.close_session`, `stream_reply_open`, `stream_priority`, `stream_stop` | io-table ops appended at the end, shaped as `wired_server_wt_close_session`, `wired_server_wt_stream_reply_open`, `wired_server_wt_stream_priority` and `wired_server_wt_stream_stop`. A 0 op keeps the old behavior (no close, no per-request streams, default urgency, an unroutable inbound data stream left to drain unread). |

Multi-draft negotiation (`src/app/moqt/ver/moqver.h`) follows the same
additive rule: `wired_moqt_wt_protocols` writes the server's offered
subprotocol list for `wired_srvrun_opt.wt_protocols`; an application that
does not call it (or passes a single fixed `"moqt-19"` string, as before)
keeps negotiating draft-19 only, unchanged from prior behavior. A session
whose peer sends no WT subprotocol likewise falls back to the draft-19
control-stream behavior that predates multi-draft support. The guide's
MoQT samples set `wt_protocols = "moqt-22"` and their clients offer
`moqt-22`; `examples/moqt_chat` offers the full list, so a browser that can
offer `moqt-22` (WebTransport `protocols`) runs draft-22 and one that cannot
falls back to draft-19.

Raw-QUIC MoQT (draft-ietf-moq-transport-22 6.2.2, -18/-19 3.1.4-5) adds
these application-facing names, all zero/unset = old behavior (WebTransport
only):

| Name | Role |
|---|---|
| `wired_srvboot_id.raw_alpns` | Space-separated raw application ALPNs (e.g. `"moqt-22 moqt-19 moqt-18"`) the server may select beside `h3`/`hq-interop`, in the client's preference order; 0 = off. |
| `wired_srvrun_opt.raw_on_session`, `raw_session_ctx`, `wired_rawq_on_session` | Called once per raw-ALPN connection when the handshake is confirmed, with its implicit session and the negotiated ALPN, before any of its stream bytes; the session then flows through the same `wt_on_*` callbacks. Appended last, 0 = no raw sessions reported. |
| `wired_server_session_is_raw` | 1 for a raw-QUIC implicit session, 0 for a WebTransport session. On a raw session, `wired_server_wt_close_session` sends CONNECTION_CLOSE (0x1d) with the code, resets carry the code unmapped, and datagrams carry no quarter-stream-id. |
| `wired_moqraw_io` (`qraw/moqrawio.h`) | A ready-made `wired_moqt_io` over `wired_server_wt_*` for `wired_moqt_init`. It adds the WebTransport stream signal to the stream-opening ops of WT sessions only (a raw-QUIC session's streams carry none). `send_uni2` is 0; an application that needs it sets its own. |
| `wired_moqt_on_session_raw` (`run/moqtrun.h`) | Shaped as `wired_rawq_on_session` (pass it as `raw_on_session` with the hub as `raw_session_ctx`): the ALPN `moqt-NN` picks the draft, the control streams are the uni pair, PATH/AUTHORITY Setup Options are accepted when well-formed (MALFORMED_PATH 0x9 / MALFORMED_AUTHORITY 0x1A otherwise), a GOAWAY carries an empty New Session URI, and a full hub closes the session INTERNAL_ERROR. |
| `wired_moqt_hub.raw_policy` (a `moqraw_policy`) | Optional `accept_path` / `accept_authority` hooks for raw sessions' well-formed PATH/AUTHORITY; a refusal closes INVALID_PATH (0x8) / INVALID_AUTHORITY (0x19). Zero (the `wired_moqt_init` default) accepts every well-formed value. |
| `WIRED_MOQTRUN_CLOSE_MALFORMED_PATH`, `WIRED_MOQTRUN_CLOSE_MALFORMED_AUTHORITY` | The 0x9 / 0x1A session termination codes above. |

---

**Next:** [API reference](https://hakkadaikon.github.io/wired/) — full
signatures for everything above. ([all docs](README.md))

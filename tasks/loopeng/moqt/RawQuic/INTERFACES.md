# Raw-QUIC MoQT: frozen interfaces (S0a, ledger 13-1)

Status: frozen 2026-10-05 against base `7e7a0dd`. The source of truth is the
headers below; their doc comments carry the contract and the spec citations.
Plan: `plan.md` §4/§6/§7. Code against these declarations and do not rename
them. If a signature must change, change it here and in the header in the
same step, and tell the aggregator.

No `.c` stubs were created. Every new function is declared only and nothing
calls it yet, so `just ninja` and the unity build are unaffected. Each step
below creates its own `.c` + `*_test.c`; S12 wires `tests/run.c`.

## New headers

### `src/tls/ext/salpn/salpn_raw.h` -> S1 (`salpn_raw.c`, `tests/tls/salpn_raw_test.c`)

| Declaration | Step |
|---|---|
| `int salpn_raw_list_has(const char* list, const u8* name, usz name_len)` | S1 |
| `salpn_choice salpn_raw_pick(const u8* alpn_ext_data, usz len, const char* raw_list, wired_span* tok)` | S1 (S6 calls it from `sdrv_negotiate_alpn`) |

S1 note (unity build): `negotiate.c` already has these `static`s: `list_end`,
`salpn_entry_choice`, `salpn_name_choice`, `salpn_entry_matches`, and
`alpn_match_fn`. Do NOT reuse those names; prefix your statics with
`salpn_raw_`. Use `tls_alpn_is_h3/hq` (`tls/handshake/core/tls/alpn_match.h`).

### `src/app/rawquic/rawq.h` -> S2 (`rawq.c`, `tests/app/rawq_test.c`)

| Declaration | Step |
|---|---|
| `RAWQ_NO_CONNECT_ID` `((u64)-1)` | S2 (used by S9) |
| `RAWQ_UNI_FIRST_RAW` 3, `RAWQ_UNI_FIRST_H3` 11 | S2 |
| `rawq_route_kind` {`RAWQ_ROUTE_REQUEST_H3`, `_WT_BIDI`, `_WT_UNI`, `_RAW_BIDI`, `_RAW_UNI`, `_H3_UNI`} | S2 (used by S7) |
| `rawq_route_kind rawq_route(int raw, u64 stream_id, wired_span first)` | S2 |
| `u64 rawq_reset_code_out(int raw, u32 app)` | S2 (used by S9) |
| `int rawq_reset_code_in(int raw, u64 wire, u32* app)` | S2 (used by S9) |
| `usz rawq_dgram_prefix_len(int raw, u64 connect_stream_id)` | S2 (used by S9) |
| `u64 rawq_uni_first_id(int raw)` | S2 (used by S9) |

S2 note: `dispatch.c` has a `static is_wt_stream_signal`; do not reuse that
name.

### `src/app/moqt/qraw/moqraw.h` -> S3 (`moqraw.c`, `tests/app/moqraw_test.c`)

| Declaration | Step |
|---|---|
| `MOQRAW_CLOSE_INVALID_PATH` 0x8, `_MALFORMED_PATH` 0x9, `_INVALID_AUTHORITY` 0x19, `_MALFORMED_AUTHORITY` 0x1A | S3 |
| `moqraw_policy` {`accept_path`, `accept_authority`, `ctx`} | S3 (S10 adds `wired_moqt_hub.raw_policy`) |
| `int moqraw_path_ok(wired_span path)` | S3 |
| `int moqraw_authority_ok(wired_span authority)` | S3 |
| `u32 moqraw_setup_verdict(int raw, const moqctl_setup* m, const moqraw_policy* pol)` | S3 (S10 calls it from `moqtrun_setup_opt_bad`) |

### `src/app/moqt/qraw/moqrawio.h` -> S4 (`moqrawio.c`, `tests/app/moqrawio_test.c`)

| Declaration | Step |
|---|---|
| `MOQRAWIO_STAGE_BUF` 65536 | S4 |
| `moqrawio_backend` {`is_raw`, `open_bidi_stream`, `open_uni`, `open_uni_stream`} | S4 |
| `wired_moqt_io moqrawio_io(const moqrawio_backend* be)` | S4 (test seam: a recorder backend) |
| `wired_moqt_io wired_moqraw_io(void)` | S4 (used by the S11 example) |

## Additions to existing headers (declarations and fields only)

| Header | Declaration | Implemented by |
|---|---|---|
| `src/tls/ext/salpn/negotiate.h` | enum member `SALPN_RAW` (appended after `SALPN_HQ`) | produced by S1 `salpn_raw_pick`; consumed by S6/S7/S9 |
| `src/app/http3/server/srvboot/srvboot.h` | `wired_srvboot_id.raw_alpns` (`const char*`, 0 = off) | S8 (into the sdrv/server init plumbing from S6) |
| `src/app/http3/server/srvrun/srvrun.h` | typedef `wired_rawq_on_session(void* app_ctx, wired_wt_session* s, wired_span alpn)` | S9 |
| `src/app/http3/server/srvrun/srvrun.h` | `wired_srvrun_opt.raw_on_session`, `.raw_session_ctx` (appended last) | S9 |
| `src/app/http3/server/srvrun/srvrun.h` | `int wired_server_session_is_raw(wired_wt_session* s)` | S9 (S4's `wired_moqraw_io` backend points at it) |

S0a already did the constructor sweep: the positional `wired_srvrun_opt`
initializers (`default_opt` in `srvrun.c`, and two in
`tests/app/srvrun_test.c`) each got two trailing `0`s. Any later field
addition must repeat this sweep.

## Left to later steps (not frozen here; the owner decides the exact form)

| Name (plan §4.2) | Owner step | Note |
|---|---|---|
| `salpn_build_response_tok` | S6 (`negotiate.{h,c}`) | builds the EE ALPN from the chosen token; reuses the static `build_alpn_ext` in `negotiate.c` |
| `sdrv_init_in.raw_alpns`, `sdrv.alpn_tok`, server init field | S6 | threads `raw_alpns` from srvboot (S8) into sdrv |
| `wired_moqt_on_session_raw`, `wired_moqtrun_peer.raw`, `wired_moqt_hub.raw_policy` | S10 | other agents own `moqtrun.{h,c}` until S10 |

## Deviations from plan §4.2

- Dropped `salpn_negotiate_raw`. It would be the same client-order walk as
  `salpn_raw_pick` (MECE), so S6 calls `salpn_raw_pick` directly from
  `sdrv_negotiate_alpn`.
- `rawq_dgram_prefix_len` also takes `connect_stream_id`. The WT prefix
  length is the length of the qsid varint, which depends on it. On raw the
  result is always 0.
- `moqraw_policy` has two hooks (`accept_path`, `accept_authority`) instead
  of one `accept(ctx, path, authority)`. A refusal must map to either 0x8 or
  0x19, and a single hook cannot say which option it refused.
- Added the `MOQRAW_CLOSE_*` and `MOQRAWIO_STAGE_BUF` constants and the
  `moqrawio_backend` / `moqrawio_io` test seam. Plan §6 S4 describes the seam
  but §4.2 does not name it. `moqtrun.h` has no MALFORMED_* close macros yet.
- The rawq "close kind" helper from plan §4.1 is not declared (YAGNI). S9
  branches on the connection's raw bit (`wired_server_session_is_raw`).

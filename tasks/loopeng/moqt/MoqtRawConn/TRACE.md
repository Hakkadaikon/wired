# MoqtRawConn: model-to-code trace table (plan step S5)

This table maps each model action and property to the function that implements
it in the planned design (plan §4 and §6), and to the test that must pin it 1:1.

- "today" is the current code at `7e7a0dd`.
- "new" is a planned name from plan §4.2. Re-grep each one before writing it.
- Tests use the plan §7 ids. A **(new)** id is a test that this model adds to
  the list.

## Actions

| model action | planned implementation (file : function) | today | test |
|--------------|------------------------------------------|-------|------|
| `ClientHello` / `Pick` | `tls/ext/salpn/salpn_raw.c : salpn_raw_pick` (client order over h3/hq/raw list) via `negotiate.c : salpn_negotiate_raw`, called from `sdrv.c : sdrv_negotiate_alpn` | `salpn_negotiate` (h3/hq only) | T-A1, T-A2, T-A3 |
| `ClientHello` (a = "none") | `sdrv` keeps `SALPN_NONE` → `eebuild` returns 0 → handshake fails with `no_application_protocol` (0x178) → `srvrun_open_done(ok=0)` → `srvrun_free_slot` | same path | T-A2 (NONE rows), **(new) T-E11**: no `raw_on_session`/`wt_on_session` for an hq or failed-ALPN connection |
| `Confirm` (h3) | `srvloop/respond.c : build_settings_frame` gate `alpn == SALPN_H3` (unchanged) | same | T-E1 (raw: no SETTINGS) |
| `Confirm` (raw) → `CreateSess` | `srvrun.c : srvrun_on_step`, a new call **between `wired_srvloop_step` and `srvrun_offer_wt_streams`** (for example `srvrun_raw_start(cfg, c)`, which is static): on the first step where `wired_server_is_confirmed(&c->s)` holds and `sdrv.alpn == SALPN_RAW` and `!wt_active`, it runs `wired_wt_session_init(slot0, RAWQ_NO_CONNECT_ID)`, `flow_control = 0`, `establish`, `wt_active = 1`, then `cfg->raw_on_session(ctx, s, tok)`. Do **not** put it next to `srvrun_start_wt` (`srvrun_sess_on_step` → `srvrun_start_done_resps`), which runs after delivery (D3) | — | T-E8 (first half), **(new) T-E12** (coalesced Finished + SETUP delivered in the same datagram) |
| `WtConnect` | `srvrun.c : srvrun_start_wt` → `srvrun_wt_notify` (unchanged) | same | existing WT tests |
| `PeerStream` | `srvloop/dispatch.c`: an early `rawq_route(...)` branch when `sdrv.alpn == SALPN_RAW` → `wt_streams[]` / `wt_uni_streams[]` with `sig_len = 0` | 0x41/0x54 classification only | T-B1, T-E3 |
| `Deliver` + `DeliverGate` | `srvrun.c : srvrun_offer_and_deliver_wt[_uni]_slot` → `srvrun_deliver_wt_stream_delta`, gated by `wt_stream_delta_ready` (`sidx >= 0`) **and** "connection not closing" (new). Pass `slot->wt_session_slot` as sidx (the D1 fix), not `srvrun_wt_slot_for_new_stream` | first-active recompute (D1); no closing gate (D2) | T-E3, T-E8, **(new) T-E13** (D1), **(new) T-E14** (D2) |
| `Deliver` (verdict) | `app/moqt/qraw/moqraw.c : moqraw_setup_verdict(raw, setup, policy)`, called from `moqtrun.c : moqtrun_setup_take_code` in place of `moqtrun_setup_opt_bad` | `moqtrun_setup_opt_bad` (WT rule for everyone) | T-C1 to T-C4, T-F2, T-F3 |
| `HubClose` | `moqtrun.c : moqtrun_peer_close` → `io.close_session` → `moqrawio` → `srvrun.c : wired_server_wt_close_session` (latch `wt_close_pending`) | same latch | T-F4 |
| `DrainClose` → `DrainWt` | `srvrun.c : srvrun_drain_wt_close_one` → `srvrun_send_wt_close` → `srvrun_close_wt_session_slot` (unchanged) | same | existing WT close tests |
| `DrainClose` → `DrainRaw` | `srvrun_drain_wt_close_one`: when the conn is raw, a new static `srvrun_raw_close(cfg, c, code, msg)` runs, in this order: (1) `srvrun_send_app_close(code, msg)`, type 0x1d; (2) enter the closing state with a new `c->closing` latch, so that the pump, offer/deliver and every send API become no-ops; (3) `srvrun_close_wt_session_slot(cfg, c, 0, …)`, which does notify → `wt_active = 0` **in the same step** | — | T-E5 (pinned `1d 03 00` / `1d 08 08 …`), T-E8 |
| `ViolationClose` | every `srvrun_send_app_close` / `srvrun_send_transport_close` caller (`srvrun.c` 2478, 3884, 3918, 3930ff, 8922, 10186) goes through one helper that also sets `c->closing` and closes every active session (the `srvrun_close_all_wt` body without freeing the slot) | frame only (D2) | **(new) T-E14** |
| `Goaway` | `srvrun.c : srvrun_goaway_applies` (`alpn == SALPN_H3`, unchanged) | same | T-E1 (shutdown row) |
| `ConnEnd` | `srvrun.c : srvrun_free_slot` → `srvrun_close_all_wt` (notify only the **active** slots); callers are `srvrun_step_and_reap` (peer close), `srvrun_sweep_idle`, `srvrun_pto_slot`, `srvrun_rst_retry_slot`, `srvrun_boot_pto_slot`, `srvrun_open_done`. Closing-period end: `srvrun_sweep_idle` should also reap a `closing` conn after 3×PTO (RFC 9000 §10.2) instead of 30 s idle | same, minus the closing state | T-E8 (peer close / idle rows) |
| `RawCreateLate` (mutation only) | must not exist: no raw session creation in `srvrun_sess_on_step` | — | T-E8 |

## Invariants and properties

| property | enforced by | test |
|----------|-------------|------|
| `SessBeforeData` | the raw session is created before `srvrun_offer_wt_streams` in `srvrun_on_step`. The `wt_stream_delta_ready` `sidx >= 0` gate stays | T-E8, T-E12 |
| `CloseOnce` | `srvrun_close_wt_session_slot` and `srvrun_close_all_wt` both clear `wt_active` right after notifying, and the raw close goes through `srvrun_close_wt_session_slot`. Never notify without clearing | T-E8 (hub close, then idle: one close) |
| `CloseIffSession` | `srvrun_free_slot` → `srvrun_close_all_wt` runs before `conntable_remove`. `srvrun_open_slot` zeroes the conn | T-E8 |
| `NoGhost` | pointer-to-conn lookup requires `up && active` (`wt_slot_holds_session`). Delivery uses the stream's own `wt_session_slot` (D1). No delivery after close (D2) | T-E8 (reuse row), T-E13 |
| `NoH3OnRaw` | `build_settings_frame` / `srvrun_goaway_applies` keep `== SALPN_H3`. Never write `!= SALPN_HQ` | T-E1 |
| `RawCloseShape` | `wired_server_wt_close_session` → `srvrun_raw_close` for raw, the capsule for WT. The branch is `wired_server_session_is_raw` | T-E5, T-F4 |
| `PathRule` | `moqraw_setup_verdict` exhaustive table | T-C1 to T-C4, T-F2, T-F3 |
| `NoDataAfterClose` | the `c->closing` latch checked in offer/deliver (and in pump/send) | T-E14 |
| `SingleCloseFrame` | `c->closing` makes every later `srvrun_send_app_close` / `srvrun_raw_close` a no-op (except the RFC 9000 §10.2.1 echo of the **same** frame) | T-E14 |
| `SessOnlyOnApp` | raw creation is gated on `SALPN_RAW`, WT creation on Extended CONNECT | T-E11 |
| `EstablishLive` (L1) | `moqraw_setup_verdict` accepts well-formed PATH/AUTHORITY on raw | T-F2, T-L1 |
| `CloseLive` (L2) | `srvrun_raw_close` notifies in the same step, without waiting for the idle sweep or the peer | T-E8, T-E14 |

## New test ids this model adds (append to plan §7.5)

- **T-E11**: an hq-interop connection and a failed-ALPN attempt produce no
  session callback.
- **T-E12**: one datagram carries the client Finished plus a 1-RTT STREAM
  frame (uni 2, SETUP). `raw_on_session` then `wt_on_stream_data` fire while
  that datagram is processed, with no second datagram needed.
- **T-E13** (WT, D1): two sessions with flow control. Close slot 0, offer a
  stream to slot 1, establish a new session in slot 0, then deliver the next
  chunk. The callback's session pointer must be slot 1's.
- **T-E14** (D2):
  - after `close_session` on raw, or after any violation CONNECTION_CLOSE on
    WT or raw, `wt_on_session_close` fires in the same step;
  - a later client packet produces no `wt_on_stream_data`, no STREAM frame,
    and at most a resent identical CONNECTION_CLOSE;
  - a second close attempt sends no different code.

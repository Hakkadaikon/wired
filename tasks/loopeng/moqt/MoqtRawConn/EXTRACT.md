# MoqtRawConn: requirements and variables (ledger 13-2, plan S0b)

Scope: the lifecycle from a QUIC connection to a raw MoQT session: creation,
delivery, close, and slot reuse. The model also covers the WT session on the
same server slot, because both kinds share one `wired_wt_session` slot and the
same app callbacks.

Sources:

- Spec text: `tasks/specs/draft-ietf-moq-transport-{18,19,22}.txt`. Line
  numbers below are the section headings in those files.
- RFC 9000: fetched from rfc-editor.org (`rfc9000.txt`) on 2026-10-05, for
  §10.2 and §10.2.1 only.
- Code: the main tree, read-only, at HEAD `7e7a0dd`.
- Plan: `tasks/loopeng/moqt/RawQuic/plan.md` §1 (R1-R17), §3.4 (S1-S11) and
  §4 (design).

## Spec requirements modelled

| id | level | text (section) | model element |
|----|-------|----------------|---------------|
| M1 | MUST | MOQT over native QUIC or WT. The ALPN is `moqt-NN`, and the client lists MOQT ALPNs and h3 in preference order. If the server picks an MOQT ALPN the session is native QUIC; if it picks h3, it is WT (d18 §3.1 l.1257 + §3.1.2 end; d19 §3.1 l.1306; d22 §6.1.2 / §6.2 l.2448). | `Pick`, `Transport`, `ClientHello` |
| M2 | MUST (RFC 7301 §3.2) | No overlap fails the handshake (`no_application_protocol`, which is CONNECTION_CLOSE 0x178 on QUIC). No session exists (plan R11). | `ClientHello` (a == "none"), `SessOnlyOnApp` |
| M3 | — | Native QUIC has no CONNECT. The session exists once the QUIC connection exists (d18 §3.1.4 l.1373, d19 §3.1.5 l.1432, d22 §6.2.2 l.2505). wired creates it at handshake confirmation and refuses 0-RTT (REQ-H). | `Confirm` → `CreateSess` |
| M4 | SHOULD / MAY | Request or object streams that arrive before the control streams/setup are buffered (or reset) (d18 §3.3 l.1465, d19 §3.3 l.1525, d22 §6.3 l.2525). The transport must never hand bytes to the app for a session the app does not know. | `PeerStream` → `pend`, `DeliverGate`, `SessBeforeData` |
| M5 | MUST | AUTHORITY (0x05): client-only, native-QUIC-only. On WT, from the server, or naming an unsupported authority → INVALID_AUTHORITY 0x19. Not RFC 3986 → MALFORMED_AUTHORITY 0x1A (d18 §10.3.1.1 l.3554, d19 §10.3.1.1 l.3890, d22 §9.1.1 l.3930). | `SpecVerdict`, `PathRule` |
| M6 | MUST | PATH (0x01): same shape. On WT or unsupported → INVALID_PATH 0x8. Not RFC 3986 → MALFORMED_PATH 0x9 (d18 §10.3.1.2 l.3571, d19 §10.3.1.2 l.3907, d22 §9.1.2 l.3947). A conforming raw client MUST send them (`moqt` URI), so a raw server that applies the WT rule closes every conforming client. | `SpecVerdict`, `PathRule`, `EstablishLive` |
| M7 | MUST | Termination on native QUIC uses CONNECTION_CLOSE (RFC 9000 §19.19); on WT it uses CLOSE_WEBTRANSPORT_SESSION. Codes are the Session Termination codes (d18 §3.5 l.1664, d19 §3.5 l.1762, d22 §6.6 l.2818 + §12.2 l.6733). | `DrainRaw` / `DrainWt`, `RawCloseShape` |
| M8 | MUST | Raw QUIC has no HTTP/3. A raw connection has no H3 control stream, SETTINGS, QPACK or H3 GOAWAY (plan REQ-C; a server uni stream id 3 is MoQT's). | `SettingsGate`, `Goaway`, `NoH3OnRaw` |
| Q1 | RFC 9000 §10.2 | "A CONNECTION_CLOSE frame causes all streams to immediately become closed; open streams can be assumed to be implicitly reset. After sending a CONNECTION_CLOSE frame, an endpoint immediately enters the closing state." | `CloseTearsDown`, `NoDataAfterClose` |
| Q2 | RFC 9000 §10.2.1 | "In the closing state, an endpoint retains only enough information to generate a packet containing a CONNECTION_CLOSE frame…" The endpoint sends only CONNECTION_CLOSE in response to incoming packets, so there is one close frame and one code per connection. | `SingleCloseFrame` |
| A1 | API contract (`srvrun.h` `wired_wt_on_session_close`) | Fires **once per session, before the session object's storage can be reused by a later connection**. An app that keys state on the pointer MUST release it here. | `CloseOnce`, `CloseIffSession`, `NoGhost` |
| A2 | plan §4.4 | `raw_on_session` is called **before** any stream byte of that step is delivered. | `SessBeforeData` |

Out of scope here; covered by the TDD tables in plan §7:

- qsid-free datagrams (R14);
- reset code identity (R12);
- the server uni stream id start of 3 (S1);
- 0-RTT refusal (R16);
- the RFC 3986 grammar itself, which the model abstracts into the option
  shapes BADPATH, BADAUTH and REFPATH.

## Implementation facts the model encodes (code at `7e7a0dd`)

| fact | where |
|------|-------|
| ALPN walks the **client** list and returns the first h3/hq. The header doc ("server's fixed preference order -- h3 first") and the sdrv comment are stale (D4) | `tls/ext/salpn/negotiate.c:78`, `negotiate.h`, `sdrv.c:420-431` |
| SETTINGS are only for `SALPN_H3` | `srvloop/respond.c:62-67` `build_settings_frame` |
| H3 GOAWAY is only for `SALPN_H3` | `srvrun.c:4164` `srvrun_goaway_applies` |
| Per step: `wired_srvloop_step` (confirm happens inside) → `srvrun_offer_wt_streams` / `_uni_streams` (offer + deliver) → … → `srvrun_drain_wt_close_pending` → (later, in `srvrun_sess_on_step`) `srvrun_start_done_resps` → `srvrun_start_wt` | `srvrun.c:4050-4086`, `srvrun.c:8531` |
| Delivery is skipped while no session slot is active (`sidx < 0`). The bytes stay in the slot table, are delivered later, and only on a later **peer datagram**: ticks do not run offer/deliver | `srvrun.c:2369` `wt_stream_delta_ready`, `2404` |
| Offer records `slot->wt_session_slot` = first active slot; delivery **recomputes** first active (D1) | `srvrun.c:2312/2456`, `2642/2682` |
| `wired_server_wt_close_session` latches `wt_close_pending[sidx]` (requires the session to be owned/active); `srvrun_drain_wt_close_one` clears it, then acts only if active | `srvrun.c:5378`, `3712` |
| `srvrun_close_wt_session_slot`: notify → `wired_wt_session_close` → reset owned streams → `active = 0` | `srvrun.c:3366-3383` |
| `srvrun_free_slot` → `srvrun_close_all_wt`: notify every **active** slot, then `active = 0` | `srvrun.c:5706-5716` |
| `srvrun_open_slot` zeroes the whole `srvrun_conn` on reuse (latches included) | `srvrun.c:9424` |
| Session pointer → conn lookup requires `c->up` and an active slot holding that pointer; a stale pointer resolves to nothing | `srvrun.c:4483-4530` |
| `srvrun_send_app_close` only seals and sends the frame. There is **no closing state**, no session teardown and no `on_session_close`. The connection stays `up` and keeps stepping (delivering, pumping) until the idle sweep (30 s, `WIRED_SRVRUN_IDLE_MS`, reset by every received packet) or a peer CONNECTION_CLOSE (D2) | `srvrun.c:2038-2046`; callers 2478, 3884, 3918, 8922, 10186; `srvrun_send_transport_close` the same |
| Hub: `moqtrun_setup_opt_bad` closes on any PATH/AUTHORITY (the WT rule) | `moqtrun.c:3999` |
| Hub: `moqtrun_peer_close` sets `p->closing` after `io.close_session`. `wired_moqt_on_session_close` frees the peer (`p->in_use = 0`) and does not call `close_session` | `moqtrun.c:4122`, `6804` |

## Model variables

| variable | meaning | code counterpart |
|----------|---------|------------------|
| `conn[c]` | idle / hs / confirmed / closing / gone | `c->up`, `wired_server_is_confirmed`, planned closing latch |
| `alpn[c]` | selected token | `sdrv.alpn` (+ planned `alpn_tok`) |
| `opt[c]` | SETUP option shape the client sends | `moqctl_setup.has_path/has_authority` + validity |
| `slot` | which attempt owns the `srvrun_conn` memory | `st->conns[i]` claim (`srvrun_open_slot` / `srvrun_free_slot`) |
| `sessActive` | `wt_active` (slot 0) | `srvrun_wt_active_slot(c,0)` |
| `hub[c]`, `hubErr[c]` | hub peer state and SETUP-verdict close code | `wired_moqtrun_peer` (`in_use`, `closing`, `moqsess`) |
| `pend[c]`, `sent[c]` | chunks reassembled but undelivered, and chunks sent | `wt_streams[]` / `wt_uni_streams[]` `delivered_len` vs frontier |
| `latch[c]` | `wt_close_pending` + `wt_close_code` | same |
| `appEv` | app callback history (`session`/`data`/`close`) | `raw_on_session`/`wt_on_session`, `wt_on_stream_data`, `wt_on_session_close` |
| `wire[c]` | frames emitted: H3CTRL, H3GOAWAY, `<<CC,code>>` (0x1d hub), CCX (other CONNECTION_CLOSE), `<<CLOSE_WT,code>>`, ALERT_NO_ALPN (0x178) | packets sent |
| `ccCount`, `ccAt` | CONNECTION_CLOSE frames sent, and the history index at the first one | — |
| `setupLog` | verdicts the hub took | `moqraw_setup_verdict` results |

## Model switches

| switch | base | meaning |
|--------|------|---------|
| `MutLateSession` | FALSE | raw bytes reach the app without the session gate, and the session is created in a later pass |
| `MutWtPath` | FALSE | the WT PATH/AUTHORITY rule is used on raw (today's hub) |
| `MutH3Gate` | FALSE | SETTINGS gate `alpn != HQ` instead of `== H3` |
| `MutKeepActive` | FALSE | raw close notifies but leaves `wt_active = 1` |
| `CloseTearsDown` | TRUE | a server CONNECTION_CLOSE enters the closing state and ends the session now (FALSE = today's `srvrun_send_app_close`) |
| `ViolationsOn` | TRUE | the environment can trigger a connection-level violation close |

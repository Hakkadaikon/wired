# Notes for S9 (srvrun.c raw sessions), collected from the phase-1/2 coders

## From S2+S7 (rawq.c, srvloop dispatch)
- Raw slots arrive with in_use=1, offered=0, sig_len/type_len=0. srvrun_offer_wt_slot / srvrun_offer_wt_uni_slot attach them to whatever session srvrun_wt_slot_for_new_stream(c) returns, so the raw implicit session must exist (and be established) before that offer runs in the same step (also TLA+ D3), or the streams stay reassembled but never offered.
- Nothing parses a session id from the slot's sig[] on raw; it stays empty.
- A full bidi table on raw still queues wired_srvloop_wt_refuse, and srvrun_reject_wt_slot sends WTERR_BUFFERED_STREAM_REJECTED (HTTP/3-space). On raw send a raw code via rawq_reset_code_out or a MoQT code.
- DATAGRAM frames are still queued unchanged into rx_datagrams; skipping the qsid parse on raw is S9's job.
- h3 GOAWAY and control/QPACK stream opening stay h3-gated where they were.

## From S3+S4 (moqraw.c, moqrawio.c)
- `wired_server_session_is_raw` is declared in srvrun.h but not defined. moqrawio.c uses a placeholder static `moqrawio_srv_is_raw` (always 0) in `g_moqrawio_srv`; S9 must replace it with `wired_server_session_is_raw` and delete the placeholder.
- moqt_interop's old open_signalled used bidi=0 for open_bidi_stream (uni signal 0x54 on a bidi control stream); the mux now sends 0x41 correctly.
- S10: call `moqraw_setup_verdict(peer->raw, m, &hub->raw_policy)` from `moqtrun_setup_opt_bad`; raw=0 returns today's codes, a null policy accepts every well-formed value.
- io ops take no context, so the backend is process-wide (last `moqrawio_io` wins); a hub must call `wired_moqraw_io()` itself.
- On raw, open_bidi_stream returns -1 and send_budget returns (usz)-1 (relies on QUIC MAX_DATA; S9 must confirm srvrun enforces it).

## From the MoqtRawConn review (REVIEW.md)
- F4 (S10): when the hub has no free session slot, wired_moqt_on_session just returns; the session is never answered/closed until the idle sweep. wired_moqt_on_session_raw must call close_session(INTERNAL_ERROR) on allocation failure, with a test.
- F5: T-E12 (coalesced Finished + SETUP) is mandatory; create the raw session between wired_srvloop_step and srvrun_offer_wt_streams (D3).
- F2: malformed PATH/AUTHORITY on WT may be 0x8/0x19 or 0x9/0x1A per spec; we pin 0x8/0x19 (design decision).
- F8: add T-E11..T-E14 to plan §7.5.

## From S1+S6+S8 (ALPN / TLS / srvboot)
- Raw vs h3: test `c->s.sdrv.alpn == SALPN_RAW`. The token for raw_on_session is `c->s.sdrv.alpn_tok` (a view into id->raw_alpns; empty for h3/hq).
- raw_alpns is set via `sdrv_set_raw_alpns` (called from srvboot_init), not an sdrv_init_in field. srvrun_slot_id copies wired_srvboot_id, so raw_alpns reaches every slot.
- respond.c already skips the H3 control stream unless ALPN is h3.
- 0-RTT is never accepted on raw; no early-data handling needed for raw sessions.
- No ALPN match → no_application_protocol (0x178) via sdrv_last_error.

## From the srvrun close fixes (12-21..12-23)
- Raw hub close: call srvrun_send_app_close(cfg, c, code, reason). It sends, enters closing, and notifies on_session_close once via srvrun_close_all_wt. No need for srvrun_close_wt_session_slot.
- c->closing is the single "connection is over" latch; gate any new raw-only send/delivery path on it or route it through srvrun_send.
- srvrun_close_send computes the reap time from c->l.now_ms (a close from a tick path uses the last step's clock).
- srvrun_close_wt_on_stream_close also fires on peer STOP_SENDING (dispatch latches FIN/RESET/STOP alike) → server FINs where RFC 9000 3.5 wants RESET_STREAM. Needs dispatch to tell them apart.
- transport/conn/lifecycle/closelife models these phases in ticks; srvrun doesn't use it.

## From S9 (for S10/S11/S12)
- S10: wire opt.raw_on_session = wired_moqt_on_session_raw (srvrun copies it into the env). Session pointer is &c->wt (slot 0); connect_stream_id = RAWQ_NO_CONNECT_ID.
- close_session on raw closes the whole connection with 0x1d; on_session_close fires synchronously in that step; then closing. close_session from inside raw_on_session (F4) is drained in the same step.
- wired_server_wt_drain_session returns 0 on raw. Received resets arrive mapped=1 with the raw MoQT code.
- Raw client bidi streams use wt_streams[] (24 slots); bidi credit shared with the request-table base; an overflow stream is reset with EXCESSIVE_LOAD 0x9.
- S11: comments in examples/moqt_chat TS and justfile mentioning "6" uni slots are stale (now 9). Raw still needs peer max_datagram_frame_size before sending datagrams. Close reasons on raw cut to 48 bytes.
- S12: docs/api-stability.md rows for wired_server_session_is_raw and raw_on_session.

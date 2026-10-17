#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_grant_req_slot_credit(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_srvloop_stream_slot* slot);
static void srvrun_reset_wt_bidi_if_owned(
    const srvrun_cfg*             cfg,
    srvrun_conn*                  c,
    wired_srvloop_wt_stream_slot* slot,
    int                           session_slot,
    u64                           err_code);
static void srvrun_reset_wt_uni_if_owned(
    const srvrun_cfg*                 cfg,
    srvrun_conn*                      c,
    wired_srvloop_wt_uni_stream_slot* slot,
    int                               session_slot,
    u64                               err_code);
static void srvrun_reset_wt_send_if_owned(
    const srvrun_cfg* cfg,
    srvrun_conn*      c,
    srvrun_wtsend*    w,
    int               session_slot,
    u64               err_code);

void srvrun_grant_wt_credit(const srvrun_cfg* cfg, srvrun_conn* c) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++)
    srvrun_grant_wt_slot_credit(cfg, c, &c->l.wt_streams[i]);
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_UNI_STREAMS; i++)
    srvrun_grant_wt_uni_slot_credit(cfg, c, &c->l.wt_uni_streams[i]);
  srvrun_grant_qenc_credit(cfg, c);
  srvrun_grant_conn_credit(cfg, c);
}

/* RFC 9000 4.1/19.10: raise slot's stream credit to its window's new end
 * once the window slid (bodywin_credit_due: never past it, only growing). */
void srvrun_grant_body_credit(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_srvloop_stream_slot* slot) {
  u64 v = bodywin_credit_due(&slot->body);
  if (v) srvrun_send_max_stream_data(cfg, c, slot->stream_id, v);
}

static void srvrun_grant_req_slot_credit(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_srvloop_stream_slot* slot) {
  if (srvrun_req_credit_live(slot)) srvrun_grant_body_credit(cfg, c, slot);
}

/* RFC 9000 4.1/19.10: as a streamed request body slides its window, raise
 * that stream's credit to the window's new end (bodywin_credit_due: never
 * past it, only ever growing); the connection-wide MAX_DATA follows in
 * srvrun_grant_conn_credit (srvrun_req_rx_ceiling). */
void srvrun_grant_req_credit(const srvrun_cfg* cfg, srvrun_conn* c) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_STREAMS; i++)
    srvrun_grant_req_slot_credit(cfg, c, &c->l.streams[i]);
}

/* draft-ietf-webtrans-http3-15 SS4.4: this step's stream-close gathering
 * (dispatch.c's gather_stream_closes) latched a RESET_STREAM/STOP_SENDING/FIN
 * on the exact stream id that is one of this connection's active WT
 * sessions' own CONNECT stream -- close that one session now, independent of
 * whether the rest of the connection is still alive. This is a precise
 * per-session trigger distinct from srvrun_free_slot's own whole-connection
 * teardown: without it, a CONNECT stream closing while the connection stays
 * open would leave that session established indefinitely. c->l.closed_
 * stream_seen is consumed (cleared) here every step regardless of whether it
 * matched, mirroring datagram_violation's own per-step latch-and-clear
 * shape. */
/* The active session slot whose OWN CONNECT stream is the one this step's
 * gather_stream_closes latched, or -1 if none matches (or nothing was
 * latched) — split out of srvrun_close_wt_on_stream_close to keep its own
 * branch count at the CCN gate. Only the ONE matching slot ever closes:
 * srvrun_wt_slot_by_connect_id's own exact-match lookup is what keeps every
 * other open session on this connection untouched. */
int srvrun_wt_connect_stream_slot(const srvrun_conn* c) {
  if (!c->l.closed_stream_seen) return -1;
  return srvrun_wt_slot_by_connect_id(c, c->l.closed_stream_id);
}

/* draft-ietf-webtrans-http3-15 SS4.4: abort one still-`in_use` WT bidi
 * stream that session_slot owned with err_code (RESET_STREAM +
 * STOP_SENDING via srvrun_send_wt_busy_reset, which picks the frames the
 * stream's type allows -- a client bidi gets both halves) and free its
 * slot, so a session's teardown never leaves its own streams
 * readable/writable past the session's own lifetime. A no-op for a stream
 * this session never owned (wt_session_slot mismatch) or one already free. */
static void srvrun_reset_wt_bidi_if_owned(
    const srvrun_cfg*             cfg,
    srvrun_conn*                  c,
    wired_srvloop_wt_stream_slot* slot,
    int                           session_slot,
    u64                           err_code) {
  if (!slot->in_use || slot->wt_session_slot != session_slot) return;
  srvrun_send_wt_busy_reset(cfg, c, slot->stream_id, err_code);
  srvrun_wt_bidi_slot_free(c, slot);
}

/* Same as srvrun_reset_wt_bidi_if_owned, for one WT uni stream slot -- a
 * client-initiated uni stream gets STOP_SENDING alone (this server has no
 * send part to reset on it, RFC 9000 19.4/19.5). */
static void srvrun_reset_wt_uni_if_owned(
    const srvrun_cfg*                 cfg,
    srvrun_conn*                      c,
    wired_srvloop_wt_uni_stream_slot* slot,
    int                               session_slot,
    u64                               err_code) {
  if (!slot->in_use || slot->wt_session_slot != session_slot) return;
  srvrun_send_wt_busy_reset(cfg, c, slot->stream_id, err_code);
  srvrun_wt_uni_slot_free(c, slot);
}

/* draft-ietf-webtrans-http3-15 SS4.4/8.2: a session closing must not leave
 * any of ITS OWN WT bidi/uni streams open -- reset every one with err_code.
 * wt_session_slot (set at offer time, srvrun_offer_wt_slot/_uni_slot) is what
 * tells these apart from a sibling session's own streams when
 * SRVRUN_MAX_WT_SESSIONS > 1 sessions are open at once on the same
 * connection. */
/* draft-ietf-webtrans-http3-15 SS4.4/8.2: the streams this server itself
 * opened (or is still answering) for the closing session live in no receive
 * table, only in wtsend[] -- without this sweep the pump keeps sending
 * STREAM frames for a dead session, and an unfinished server uni stream
 * never returns the peer's uni-stream credit. srvrun_send_wt_busy_reset
 * picks the type-appropriate frames (final size = bytes sent, kept until
 * ACKed) and releases the slot. A slot the receive-table pass already
 * reset is free by now and skipped. */
static void srvrun_reset_wt_send_if_owned(
    const srvrun_cfg* cfg,
    srvrun_conn*      c,
    srvrun_wtsend*    w,
    int               session_slot,
    u64               err_code) {
  if (!w->in_use || w->wt_session_slot != session_slot) return;
  srvrun_send_wt_busy_reset(cfg, c, w->stream_id, err_code);
}

void srvrun_reset_wt_sends_for_session(
    const srvrun_cfg* cfg, srvrun_conn* c, int session_slot, u64 err_code) {
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++)
    srvrun_reset_wt_send_if_owned(
        cfg, c, &c->wtsend[i], session_slot, err_code);
}

void srvrun_reset_wt_streams_for_session(
    const srvrun_cfg* cfg, srvrun_conn* c, int session_slot, u64 err_code) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++)
    srvrun_reset_wt_bidi_if_owned(
        cfg, c, &c->l.wt_streams[i], session_slot, err_code);
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_UNI_STREAMS; i++)
    srvrun_reset_wt_uni_if_owned(
        cfg, c, &c->l.wt_uni_streams[i], session_slot, err_code);
  srvrun_reset_wt_sends_for_session(cfg, c, session_slot, err_code);
}

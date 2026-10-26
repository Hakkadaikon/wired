#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_wtsend_stop(
    const srvrun_cfg* cfg, srvrun_conn* c, const wired_srvloop_reset* e);
static void srvrun_connect_stop(
    const srvrun_cfg* cfg, srvrun_conn* c, int sidx, u64 code);
static int srvrun_critical_send(const srvrun_conn* c, u64 stream_id);
static int srvrun_stop_on_critical(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 stream_id);
static usz srvrun_req_stop(
    const srvrun_step_ctx* ctx, srvrun_conn* c, const wired_srvloop_reset* e);
static usz srvrun_answer_stream_stop(
    const srvrun_step_ctx* ctx, srvrun_conn* c, const wired_srvloop_reset* e);

/* RFC 9000 3.5 on a WT stream this server sends on: RESET_STREAM with the
 * peer's code at the bytes already sent, and stop sending. */
static void srvrun_wtsend_stop(
    const srvrun_cfg* cfg, srvrun_conn* c, const wired_srvloop_reset* e) {
  u8                   pl[SRVRUN_RST_PL];
  wired_obuf           plb = obuf_of(pl, sizeof pl);
  const srvrun_wtsend* w   = srvrun_wtsend_find(c, e->stream_id);
  if (!w) {
    return;
  }
  srvrun_wtsend_stop_notify(cfg, c, w, e);
  srvrun_send_kept(
      cfg, c, pl,
      srvrun_wt_abort_reset(c, e->stream_id, e->error_code, &plb, 0),
      "WT stream RESET sent\n");
  srvrun_wtsend_release(c, e->stream_id);
}

/* RFC 9000 3.5 on session slot sidx's CONNECT stream: reset it with the
 * peer's code (not a FIN) -- the stream's end ends the session too
 * (draft-ietf-webtrans-http3-16 6). */
static void srvrun_connect_stop(
    const srvrun_cfg* cfg, srvrun_conn* c, int sidx, u64 code) {
  srvrun_log_close(
      "wt session closed by peer (STOP_SENDING)", wired_span_of(0, 0));
  srvrun_reset_connect_stream_code(cfg, c, sidx, code);
  srvrun_close_wt_session_slot(cfg, c, sidx, WTERR_SESSION_GONE);
}

/* 1 iff stream_id is one of this server's open critical uni streams
 * (RFC 9114 6.2.1 control, RFC 9204 4.2 QPACK encoder/decoder): ids 3, 7
 * and 11, each counted only once it is open -- raw QUIC opens none, so the
 * same ids there are ordinary streams. */
static int srvrun_critical_send(const srvrun_conn* c, u64 stream_id) {
  const int open[3] = {
      c->l.h3.settings_sent != 0, c->qenc_stream_opened, c->qdec_stream_opened};
  if (stream_id > SRVRUN_QDEC_STREAM || stream_id % 4 != 3) {
    return 0;
  }
  return open[stream_id / 4];
}

/* RFC 9114 6.2.1 / RFC 9204 4.2: the peer "MUST NOT request that the sender
 * close" a critical stream -- a STOP_SENDING on one closes the connection
 * with H3_CLOSED_CRITICAL_STREAM instead of resetting the stream. */
static int srvrun_stop_on_critical(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 stream_id) {
  if (!srvrun_critical_send(c, stream_id)) {
    return 0;
  }
  srvrun_send_app_close(
      cfg, c, H3_CLOSED_CRITICAL_STREAM,
      wired_span_of((const u8*)"critical stream stopped", 23));
  return 1;
}

/* RFC 9000 3.5: a STOP_SENDING for a request whose response has not
 * started still MUST be answered with RESET_STREAM -- Final Size 0, since
 * no byte was sent -- and the request is cancelled: the rest of its body
 * is refused (STOP_SENDING, the same pair srvrun_wt_abort_pair builds),
 * and its slot is released, so a late byte opens nothing (req_closed), no
 * response ever starts, and a body streaming to the app is aborted with
 * the peer's code. 1 when a slot was freed (its stream credit is owed). */
static usz srvrun_req_stop(
    const srvrun_step_ctx* ctx, srvrun_conn* c, const wired_srvloop_reset* e) {
  u8         pl[48];
  wired_obuf plb = obuf_of(pl, sizeof pl);
  if (!srvrun_req_slot_of(c, e->stream_id)) {
    return 0;
  }
  srvrun_send_kept(
      ctx->cfg, c, pl,
      srvrun_wt_abort_pair(c, e->stream_id, e->error_code, &plb),
      "request RESET sent\n");
  wired_srvloop_slot_cancel(&c->l, e->stream_id, e->error_code);
  return 1;
}

/* Answer one peer STOP_SENDING on whichever send part its stream id names.
 * Returns 1 when a response or request slot was freed. */
static usz srvrun_answer_stream_stop(
    const srvrun_step_ctx* ctx, srvrun_conn* c, const wired_srvloop_reset* e) {
  int          sidx = srvrun_wt_slot_by_connect_id(c, e->stream_id);
  srvrun_resp* r;
  if (sidx >= 0) {
    srvrun_connect_stop(ctx->cfg, c, sidx, e->error_code);
    return 0;
  }
  srvrun_wtsend_stop(ctx->cfg, c, e);
  r = srvrun_resp_find(c, e->stream_id);
  return r ? srvrun_resp_stop(ctx, c, r, e->error_code)
           : srvrun_req_stop(ctx, c, e);
}

/* A critical stream's STOP_SENDING closes the connection
 * (srvrun_stop_on_critical); any other is answered on its stream. */
usz srvrun_answer_peer_stop(
    const srvrun_step_ctx* ctx, srvrun_conn* c, const wired_srvloop_reset* e) {
  if (srvrun_stop_on_critical(ctx->cfg, c, e->stream_id)) {
    return 0;
  }
  return srvrun_answer_stream_stop(ctx, c, e);
}

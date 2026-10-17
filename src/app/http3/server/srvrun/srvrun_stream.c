#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_resp_not_yet_idle(srvrun_resp* r);
static int srvrun_wt_rx_live(srvrun_conn* c, u64 stream_id);
static int srvrun_wtsend_app_bidi(const srvrun_wtsend* w);

/* Feed r's ring: whenever enough acknowledged space has been reclaimed
 * (wired_sendsess_ring_room), run the handler for the next body chunk
 * directly into the ring and extend the live sendsess over it -- earlier
 * bytes can still be in flight, so the stream never waits out a full-buffer
 * ACK drain the way the old fixed rounds did (the round boundary idled the
 * link ~1 RTT every 640KB, an ~8% goodput loss on the interop link). The
 * quarter-capacity threshold keeps handler calls chunky without ever
 * exceeding what a small fixed-row ring can reclaim. A handler that
 * declines mid-stream (body.len 0, more 0) simply ends the stream exactly
 * as the old round flow did. Uses r->stream_req (the round-0 copy), never
 * c->l.req -- see stream_req's own doc. */
void srvrun_resp_refill(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot, srvrun_resp* r) {
  usz room;
  if (!srvrun_resp_streaming_live(r)) return;
  room = wired_sendsess_ring_room(&r->sess, r->ring_cap);
  if (room < r->ring_cap / 4) return;
  srvrun_resp_refill_write(ctx, c, slot, r, srvrun_resp_refill_take(r, room));
}

/* Once r's session goes idle (wired_sendsess_done: every slice sent and
 * acked), either advance a streaming response to its next round or
 * free r's slot and the matching srvloop receive-side slot -- HTTP/3 never
 * reuses a stream id, so without releasing the receive slot too,
 * WIRED_SRVLOOP_MAX_STREAMS sequential requests on distinct streams would
 * permanently exhaust it. A body that borrowed a wired_srvbigbuf row returns
 * it to the pool here too (only once streaming is actually done, not
 * between rounds). */
static int srvrun_resp_not_yet_idle(srvrun_resp* r) {
  return !r->in_use || !wired_sendsess_done(&r->sess);
}

/* This connection's transport-parameter bidi stream limit (the value
 * srvrun_grant_streams raises from the first time it fires) -- 0
 * (unset), including when the test harness's own cfg carries no id at all,
 * falls back to the same built-in default the transport parameter itself
 * uses (stp_build_server_lim, server_tp.c). */
u64 srvrun_stream_limit_base(const srvrun_step_ctx* ctx) {
  u64 configured = ctx->cfg->id ? ctx->cfg->id->max_streams_bidi : 0;
  return wired_srvloop_stream_limit(configured);
}

/* Returns 1 when the slot was released (its stream-limit grant is owed),
 * 0 otherwise. A streaming slot is refilled (never released) until the
 * handler's last bytes are queued AND fully acknowledged; a momentarily
 * drained streaming sess just re-activates on the next refill's extend. */
/* Release a fully-answered request stream's reassembly slot -- UNLESS it is
 * an active WT session's CONNECT stream, which must stay claimed for the
 * session's lifetime so the peer's flow-control capsules keep landing in it
 * (srvrun_wt_rx_capsules); srvrun_close_wt_session_slot releases it then. */
void srvrun_resp_release_stream(srvrun_conn* c, u64 stream_id) {
  if (srvrun_wt_slot_by_connect_id(c, stream_id) < 0)
    wired_srvloop_slot_release(&c->l, stream_id);
}

usz srvrun_resp_reap(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot, srvrun_resp* r) {
  srvrun_resp_refill(ctx, c, slot, r);
  if (srvrun_resp_not_yet_idle(r)) return 0;
  if (r->streaming) return 0;
  srvrun_resp_release_stream(c, r->stream_id);
  srvrun_resp_release_bigbuf(ctx->cfg->env, r);
  r->in_use = 0;
  return 1;
}

/* RFC 9114 4.1.1: a response that was never armed (arm_failed) can send
 * nothing: reset its stream with H3_INTERNAL_ERROR and free it, instead of
 * leaving the slot claimed and the client waiting forever. Any other slot
 * is reaped as usual. 1 when the slot was freed. */
usz srvrun_reap_one(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot, srvrun_resp* r) {
  return r->in_use && r->arm_failed
             ? srvrun_resp_stop(ctx, c, r, H3_INTERNAL_ERROR)
             : srvrun_resp_reap(ctx, c, slot, r);
}

void srvrun_reap_resps(const srvrun_step_ctx* ctx, srvrun_conn* c, int slot) {
  usz freed = 0;
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++)
    freed += srvrun_reap_one(ctx, c, slot, &c->resp[i]);
  srvrun_grant_streams(ctx, c, srvrun_stream_limit_base(ctx), freed);
}

/* RFC 9000 3.5: answer a peer STOP_SENDING on response r with RESET_STREAM
 * carrying the peer's own error code, Final Size the bytes already sent
 * (RFC 9000 4.5), and free r -- no STREAM frame follows a RESET_STREAM
 * (3.1). Returns 1: r's stream credit is owed back like a reaped one. */
usz srvrun_resp_stop(
    const srvrun_step_ctx* ctx, srvrun_conn* c, srvrun_resp* r, u64 code) {
  u8                 pl[32];
  reset_stream_frame rs = {
      r->stream_id, code, r->sess.stream_base_offset + r->sess.q.cur};
  srvrun_send_kept(
      ctx->cfg, c, pl, reset_stream_encode(pl, sizeof pl, &rs),
      "response RESET sent\n");
  srvrun_resp_release_stream(c, r->stream_id);
  srvrun_resp_release_bigbuf(ctx->cfg->env, r);
  r->in_use = 0;
  return 1;
}

/* 1 iff stream_id still has a live WT bidi receive slot. */
static int srvrun_wt_rx_live(srvrun_conn* c, u64 stream_id) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++)
    if (srvrun_wt_reset_bidi_matches(&c->l.wt_streams[i], stream_id)) return 1;
  return 0;
}

/* 1 iff w is the send part of a bidi stream an app session owns. */
static int srvrun_wtsend_app_bidi(const srvrun_wtsend* w) {
  return !(w->stream_id & 2) && w->wt_session_slot >= 0;
}

/* draft-ietf-moq-transport-19 3.3.3: a peer that already FIN'd its half
 * cancels with STOP_SENDING alone. That FIN's delivery reaped the receive
 * slot srvrun_deliver_wt_reset_if_owned routes by, so the stop reaches
 * the app here, through the send part's own session. */
void srvrun_wtsend_stop_notify(
    const srvrun_cfg*          cfg,
    srvrun_conn*               c,
    const srvrun_wtsend*       w,
    const wired_srvloop_reset* e) {
  if (!srvrun_wtsend_app_bidi(w) || srvrun_wt_rx_live(c, e->stream_id)) return;
  srvrun_deliver_wt_reset(cfg, c, w->wt_session_slot, e);
}

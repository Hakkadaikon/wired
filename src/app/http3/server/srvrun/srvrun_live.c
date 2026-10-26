#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_raw_start(const srvrun_cfg* cfg, srvrun_conn* c);
static void srvrun_note_stream_limits(
    const srvrun_step_ctx* ctx, srvrun_conn* c);
static void srvrun_live_prepare(const srvrun_step_ctx* ctx, srvrun_conn* c);
static void srvrun_live_after(
    const srvrun_step_ctx* ctx,
    srvrun_conn*           c,
    wired_mspan            dg,
    const srvrun_rxmark*   mark);
static void srvrun_live_streams(const srvrun_step_ctx* ctx, srvrun_conn* c);

/* Native QUIC has no Extended CONNECT: the connection itself is the session
 * (-19 3.1.5). Slot 0 is established at the first step after confirmation,
 * BEFORE this step's stream offer/delivery (TLA+ MoqtRawConn D3,
 * SessBeforeData): a SETUP coalesced with the client Finished is delivered
 * in the same step. Its id is the never-on-the-wire RAWQ_NO_CONNECT_ID and
 * flow_control stays 0 (wired_wt_session_init): only RFC 9000's own credit
 * applies, there are no WT_MAX_* capsules. */
static void srvrun_raw_start(const srvrun_cfg* cfg, srvrun_conn* c) {
  if (!srvrun_raw_start_due(c)) {
    return;
  }
  wired_wt_session_init(&c->wt, RAWQ_NO_CONNECT_ID);
  wired_wt_session_establish(&c->wt);
  c->wt_active = 1;
  cfg->env->wt_usage.sessions++;
  srvrun_raw_notify(cfg, c);
}

/* RFC 9000 4.6: hand srvloop the stream limits in force this step (the
 * last MAX_STREAMS sent, else the transport-parameter value), so a frame
 * past them ends the connection with STREAM_LIMIT_ERROR. */
static void srvrun_note_stream_limits(
    const srvrun_step_ctx* ctx, srvrun_conn* c) {
  c->l.peer_stream_limit[0] = c->stream_limit_advertised
                                  ? c->stream_limit_advertised
                                  : srvrun_stream_limit_base(ctx);
  c->l.peer_stream_limit[1] = c->uni_stream_limit_advertised
                                  ? c->uni_stream_limit_advertised
                                  : wired_srvloop_uni_stream_limit();
}

/* RFC 9000 3.2 / 19.8: hand srvloop how many server streams exist, so a
 * frame naming one not opened yet is a STREAM_STATE_ERROR. The uni count
 * starts past the three H3 plumbing streams (none on raw QUIC). */
static void srvrun_note_local_streams(srvrun_conn* c) {
  c->l.local_opened[0] = c->wt_bidi_opened;
  c->l.local_opened[1] =
      (rawq_uni_first_id(srvrun_conn_is_raw(c)) >> 2) + c->wt_uni_opened;
}

/* RFC 9000 4.1 / 18.2: the connection receive limit in force -- the
 * initial_max_data this server sent (srvboot's id, STP_DEFAULT_MAX_DATA
 * when unset) or the last larger MAX_DATA (rx_max_data_advertised). */
static void srvrun_note_rx_limit(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  u64 initial      = ctx->cfg->id ? ctx->cfg->id->max_data : 0;
  c->l.rx_max_data = u64_max(
      initial ? initial : STP_DEFAULT_MAX_DATA, c->rx_max_data_advertised);
}

/* Ready c's loop for this step: the shared clock, this step's own queues,
 * the deferred ACK, the stream limits and the path-revert decision. */
static void srvrun_live_prepare(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  c->l.now_ms = ctx->now_ms; /* share srvrun's own PTO/RTT clock with
                              * ackpolicy's delayed-ACK timer, not a
                              * second one. */
  srvrun_roll_reset_window(c, ctx->now_ms);
  c->l.peer_reset_n    = 0; /* this step's own queue (wired_srvloop doc) */
  c->l.ackst.ack_defer = 1; /* RFC 9000 13.2.1: suppress the bare-ACK packet
                             * this step; the pump piggybacks the pending ACK
                             * onto a slice, or srvrun_flush_deferred_ack
                             * sends it at step end. */
  srvrun_note_stream_limits(ctx, c);
  srvrun_note_local_streams(c);
  srvrun_note_rx_limit(ctx, c);
  c->l.drop_newer = srvrun_path_reverts(ctx, c);
}

/* Right after the step: path, raw/QPACK streams, key update, receive
 * accounting. */
static void srvrun_live_after(
    const srvrun_step_ctx* ctx,
    srvrun_conn*           c,
    wired_mspan            dg,
    const srvrun_rxmark*   mark) {
  /* RFC 9000 9.3: decided after decrypt and dedup, before any send of this
   * step, so the step's ACK and data already go to the new path. */
  srvrun_path_step(ctx, c, dg, mark);
  srvrun_raw_start(ctx->cfg, c);
  srvrun_open_qpack_streams(c);
  srvrun_flush_qdec(c);
  srvrun_ku_note_rotation(c, ctx->now_ms);
  srvrun_note_recv(ctx, mark, c, dg.n);
}

/* The step's WebTransport, datagram and stream-reset follow-up. */
static void srvrun_live_streams(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  srvrun_offer_wt_streams(ctx->cfg, c);
  srvrun_refuse_wt_streams(ctx->cfg, c);
  srvrun_offer_wt_uni_streams(ctx->cfg, c);
  srvrun_grant_wt_credit(ctx->cfg, c);
  srvrun_grant_req_credit(ctx->cfg, c);
  srvrun_drain_rx_datagrams(ctx->cfg, c);
  srvrun_wt_rx_capsules(ctx->cfg, c);
  srvrun_close_wt_on_stream_close(ctx->cfg, c);
  srvrun_answer_peer_stops(ctx, c);
  srvrun_drop_held_resets(ctx, c);
  srvrun_free_reset_reqs(ctx, c);
  srvrun_deliver_wt_reset_if_owned(ctx->cfg, c);
  srvrun_flush_wt_drain(c);
  srvrun_drain_wt_close_pending(ctx->cfg, c);
  srvrun_drain_wt_stream_reset(ctx->cfg, c);
  srvrun_grant_wt_streams(ctx, c);
}

/* A later datagram on a live slot: one real-wire step, send any sealed
 * reply — unless this step's own gathering found a connection-ending
 * violation (RFC 9221 3 DATAGRAM, or draft-ietf-webtrans-http3-15 4.3's
 * mid-stream WT_STREAM signal), in which case the connection closes itself
 * instead (srvrun_close_on_step_violation), or the step observed a peer
 * CONNECTION_CLOSE (srvrun_send_step_reply's own gate). */
void srvrun_on_step_live(
    const srvrun_step_ctx* ctx, srvrun_conn* c, wired_mspan dg) {
  u8                 out[1500];
  wired_obuf         ob   = obuf_of(out, sizeof out);
  wired_srvloop_conn conn = {&c->l, &c->s};
  srvrun_rxmark      mark = srvrun_rx_mark(&c->l);
  srvrun_newtok_mark tok  = srvrun_newtok_mark_of(c);
  int                produced;
  srvrun_live_prepare(ctx, c);
  produced = wired_srvloop_step(&conn, dg, &ob);
  srvrun_live_after(ctx, c, dg, &mark);
  srvrun_live_streams(ctx, c);
  if (srvrun_close_on_step_violation(ctx->cfg, c)) {
    return;
  }
  srvrun_send_step_reply(ctx->cfg, c, produced, wired_span_of(out, ob.len));
  srvrun_send_new_token(ctx, c, &tok); /* RFC 9000 8.1.3 / 9.3 */
}

/* RFC 9000 10.2.1: a packet for a closing connection is not processed (no
 * frame reaches srvloop or the app); the close frame answers it again on
 * the 1st, 2nd, 4th, 8th, ... such packet -- the rate limit the RFC asks
 * for, so a peer that keeps sending cannot make the server amplify. */
void srvrun_closing_rx(const srvrun_cfg* cfg, srvrun_conn* c) {
  u64 n = ++c->closing_rx;
  if ((n & (n - 1)) == 0) {
    srvrun_close_resend(cfg, c);
  }
}

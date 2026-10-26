#include "app/http3/server/srvrun/srvrun_impl.h"

/* RFC 9002 A.8-A.9 for the 1-RTT space on a poll tick: the loss-detection
 * timer's two modes, time-threshold loss and the PTO. */

static int srvrun_rec_elicits(const sentmeta_pkt* p);
static int srvrun_pto_space_ok(const srvrun_conn* c);
static int srvrun_sess_new_data(
    const srvrun_conn* c, const wired_sendsess* sess, u64 credit);
static void srvrun_pto_sess(
    const srvrun_conn* c, wired_sendsess* sess, u64 credit, int in_use);
static void srvrun_pto_requeue_all(srvrun_conn* c);
static void srvrun_pto_ping(const srvrun_cfg* cfg, srvrun_conn* c);
static void srvrun_pto_probe(const srvrun_step_ctx* ctx, int slot);

static int srvrun_rec_elicits(const sentmeta_pkt* p) {
  return p->used && p->ack_eliciting;
}

/* RFC 9002 A.8: 1 while some ack-eliciting 1-RTT packet in the record is
 * neither acknowledged nor declared lost. */
int srvrun_rec_eliciting(const srvrun_conn* c) {
  for (usz i = 0; i < SENTMETA_CAP; i++) {
    if (srvrun_rec_elicits(&c->l.ackst.sent.pkts[i])) {
      return 1;
    }
  }
  return 0;
}

/* RFC 9002 6.2.1: no Application Data PTO before the handshake is
 * confirmed, and none while the loss timer is armed (A.8). */
static int srvrun_pto_space_ok(const srvrun_conn* c) {
  return c->up && wired_server_is_confirmed(&c->s) && !c->loss_time_us;
}

/* RFC 9002 A.8: the 1-RTT PTO is armed while an ack-eliciting packet --
 * STREAM, control frame or DATAGRAM (RFC 9221 5.2) -- is unacknowledged. */
int srvrun_pto_armed(const srvrun_conn* c) {
  return srvrun_pto_space_ok(c) && srvrun_rec_eliciting(c);
}

/* A.8 GetPtoTimeAndSpace: due at time_of_last_ack_eliciting_packet + PTO
 * scaled by 2^pto_count, so every ack-eliciting send restarts it (6.2.1). */
int srvrun_pto_fire_due(const srvrun_conn* c, u64 now_ms) {
  return srvrun_pto_armed(c) &&
         now_ms >= c->l.ackst.last_elicit_ms +
                       srvrun_pto_deadline_ms(c, c->l.ackst.pto_count);
}

/* 1 when sess can carry new data in a probe (srvrun_can_send_new without
 * the congestion window, RFC 9002 7.5). */
static int srvrun_sess_new_data(
    const srvrun_conn* c, const wired_sendsess* sess, u64 credit) {
  return !wired_sendq_all_sent(&sess->q) &&
         srvrun_sess_flow_room(c, sess, credit);
}

/* RFC 9002 6.2.4: probe with new data when sess has some; else queue
 * copies of its oldest in-flight slices (they stay in flight, 6.2). */
static void srvrun_pto_sess(
    const srvrun_conn* c, wired_sendsess* sess, u64 credit, int in_use) {
  if (in_use && !srvrun_sess_new_data(c, sess, credit)) {
    (void)wired_sendsess_pto_probe(sess);
  }
}

static void srvrun_pto_requeue_all(srvrun_conn* c) {
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++) {
    srvrun_pto_sess(
        c, &c->resp[i].sess, c->resp[i].stream_credit, c->resp[i].in_use);
  }
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++) {
    srvrun_pto_sess(
        c, &c->wtsend[i].sess, c->wtsend[i].stream_credit, c->wtsend[i].in_use);
  }
}

/* RFC 9002 6.2.4: nothing new or old to send -- a single PING. */
static void srvrun_pto_ping(const srvrun_cfg* cfg, srvrun_conn* c) {
  u8         pl[MIN_INITIAL_DATAGRAM];
  u8         out[1500];
  wired_obuf ob  = obuf_of(out, sizeof out);
  usz        pln = srvrun_path_payload(pl, 0, 0, 0, 1);
  wired_span d   = wired_span_of(c->l.cli_scid, c->l.cli_scid_len);
  if (srvrun_seal_path_payload(c, d, pl, pln, 0, &ob)) {
    srvrun_send(cfg, c, wired_span_of(out, ob.len), "PTO PING sent\n");
  }
}

/* RFC 9002 A.9 PTO mode: up to two ack-eliciting packets past cwnd and
 * pacing (7.5) -- new data, else retransmitted data, else a PING. */
static void srvrun_pto_probe(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c     = &ctx->st->conns[slot];
  c->l.ackst.probe_n = SRVRUN_PTO_PROBES;
  srvrun_pto_requeue_all(c);
  srvrun_pump_sess(ctx, slot);
  if (c->l.ackst.probe_n == SRVRUN_PTO_PROBES) {
    srvrun_pto_ping(ctx->cfg, c);
  }
  c->l.ackst.probe_n = 0;
}

void srvrun_pto_slot(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  c->l.now_ms    = ctx->now_ms; /* the probe's sends record it */
  if (!srvrun_pto_fire_due(c, ctx->now_ms)) {
    return;
  }
  /* The budget is connection-wide: a silent peer stopped acknowledging the
   * whole connection, not one stream. */
  if (c->l.ackst.pto_count >= SRVRUN_PTO_MAX) {
    srvrun_log_close(
        "conn dropped: probe budget exhausted", wired_span_of(0, 0));
    srvrun_free_slot(ctx->cfg, ctx->st, slot);
    return;
  }
  c->l.ackst.pto_count++;
  srvrun_pto_probe(ctx, slot);
}

/* A poll tick pumps every slot with a send session active, PTO due or not:
 * stream data the app queued from another connection's callback (a MoQT
 * hub's push when a publisher leaves) has no packet of this peer's own to
 * carry it out. */
void srvrun_send_tick_slot(const srvrun_step_ctx* ctx, int slot) {
  if (srvrun_has_outbound(&ctx->st->conns[slot])) {
    srvrun_pump_sess(ctx, slot);
  }
}

/* 1 while the loss timer is armed and has come due at now_ms. */
int srvrun_loss_timer_due(const srvrun_conn* c, u64 now_ms) {
  return c->loss_time_us && now_ms * 1000 >= c->loss_time_us;
}

/* RFC 9002 A.9 OnLossDetectionTimeout, time-threshold mode: the timer
 * fired, so run the loss pass (requeue, window, timer re-arm) without an
 * ACK, then let the pump resend what it requeued. */
void srvrun_loss_timer_slot(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  if (!c->up || !srvrun_loss_timer_due(c, ctx->now_ms)) {
    return;
  }
  c->l.now_ms = ctx->now_ms;
  srvrun_loss_pass(ctx->cfg, c, ctx->now_ms, c->largest_acked);
  srvrun_pump_sess(ctx, slot);
}

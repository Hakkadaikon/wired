#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_persistent_check(
    srvrun_conn* c, const srvrun_loss_span* s, u64 largest_before);
static int srvrun_loss_counts(
    const srvrun_conn* c, usz lost, const srvrun_loss_span* s);
static void srvrun_start_done_resp(
    const srvrun_step_ctx* ctx, int slot, u8 done_i);
static void srvrun_start_held_resp(const srvrun_step_ctx* ctx, int slot, u8 i);

/* RFC 9002 7.6.2/5.2: on persistent congestion collapse cwnd to the
 * minimum window and reset min_rtt to the newest sample. */
static void srvrun_persistent_check(
    srvrun_conn* c, const srvrun_loss_span* s, u64 largest_before) {
  if (!srvrun_loss_unbroken(c, s, largest_before)) {
    return;
  }
  if (!srvrun_loss_long(c, s)) {
    return;
  }
  cc_on_persistent(&c->cc);
  rtt_on_persistent(&c->rtt, c->latest_rtt_ms * 1000);
}

/* RFC 9000 9.4: losses only among packets sent before the congestion
 * controller was reset for a new path do not shrink it. */
static int srvrun_loss_counts(
    const srvrun_conn* c, usz lost, const srvrun_loss_span* s) {
  return lost && s->hi_pn >= c->mig.cc_from_pn;
}

void srvrun_feed_acks(
    const srvrun_step_ctx* ctx, const srvrun_cfg* cfg, srvrun_conn* c) {
  u64 largest_before = c->largest_acked;
  c->ecn_newly       = 0;
  c->ecn_sent_ms     = 0;
  for (usz i = 0; i < c->l.ack_n; i++) {
    srvrun_feed_ack_range(c, c->l.ack_lo[i], c->l.ack_hi[i], ctx->now_ms);
  }
  srvrun_rec_on_acks(c, ctx->now_ms);
  srvrun_feed_ecn(c, largest_before, ctx->now_ms);
  srvrun_loss_pass(cfg, c, ctx->now_ms, largest_before);
}

/* RFC 9002 A.10 + OnPacketsLost: the loss pass after an ACK step or a loss
 * timer expiry (largest_before = the largest acknowledged before the step,
 * or the current one when no ACK arrived). */
void srvrun_loss_pass(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 now_ms, u64 largest_before) {
  srvrun_loss_span span = SRVRUN_LOSS_SPAN0;
  usz              lost = srvrun_reap_losses_all(cfg, c, now_ms, &span);
  srvrun_pmtu_feed_losses(c, span.big);
  srvrun_rec_detect(c, now_ms);
  /* RFC 9002 7.3.1/7.3.2: cwnd shrinks once per recovery period, gated on
   * the lost packet's SEND time -- passing now here instead re-shrank the
   * window on every loss of a packet sent before the current period began,
   * pinning cwnd at CC_MIN_WINDOW under sustained light loss. */
  if (!srvrun_loss_counts(c, lost, &span)) {
    return;
  }
  cc_on_loss(&c->cc, span.newest_ms, now_ms);
  srvrun_persistent_check(c, &span, largest_before);
}

/* Send c's pending DATAGRAM (if any) using a scratch wired_obuf on the stack,
 * the same shape srvrun_send_pending_datagram expects. */
void srvrun_pump_datagram(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  u8         out[1500];
  wired_obuf ob = obuf_of(out, sizeof out);
  if (!c->dg_pending) {
    return;
  }
  srvrun_send_pending_datagram(ctx->cfg, c, &ob);
}

/* Mirror one completed request into l->req/req_stream_id and start its
 * response -- the mirror is the single-request interface srvrun_start_resp
 * reads, re-pointed here per completion so each of a step's requests is
 * answered with ITS OWN decode, not just the last one dispatch mirrored. */
static void srvrun_start_done_resp(
    const srvrun_step_ctx* ctx, int slot, u8 done_i) {
  srvrun_conn*                     c  = &ctx->st->conns[slot];
  const wired_srvloop_stream_slot* sl = &c->l.streams[done_i];
  c->l.req                            = sl->req;
  c->l.req_stream_id                  = sl->stream_id;
  srvrun_start_resp(ctx, slot);
}

/* 1 iff request slot i still holds the stream its held bit was set for. */
int srvrun_held_still(const srvrun_conn* c, u8 i) {
  return c->l.streams[i].in_use &&
         c->l.streams[i].stream_id == c->wt_held_id[i];
}

/* Process held request slot i once: clear its bit, then dispatch it like a
 * request that just completed -- unless the slot was released and reused
 * meanwhile (srvrun_held_still), when the bit is simply dropped. */
static void srvrun_start_held_resp(const srvrun_step_ctx* ctx, int slot, u8 i) {
  srvrun_conn* c   = &ctx->st->conns[slot];
  u64          bit = (u64)1 << i;
  if (!(c->wt_held_mask & bit)) {
    return;
  }
  c->wt_held_mask &= ~bit;
  if (srvrun_held_still(c, i)) {
    srvrun_start_done_resp(ctx, slot, i);
  }
}

/* WTH3-009/042: once the client's SETTINGS have arrived, every CONNECT held
 * before them (srvrun_wt_hold) is processed exactly once. */
void srvrun_start_held_resps(const srvrun_step_ctx* ctx, int slot) {
  if (!srvrun_wt_settings_ready(&ctx->st->conns[slot])) {
    return;
  }
  for (u8 i = 0; i < WIRED_SRVLOOP_MAX_STREAMS; i++) {
    srvrun_start_held_resp(ctx, slot, i);
  }
}

/* Start a response for every request that completed this step (RFC 9000
 * 2.2: a datagram may complete several request streams at once). */
void srvrun_start_done_resps(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  for (usz i = 0; i < c->l.done_n; i++) {
    srvrun_start_done_resp(ctx, slot, c->l.done_slots[i]);
  }
}

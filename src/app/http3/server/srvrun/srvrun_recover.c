#include "app/http3/server/srvrun/srvrun_impl.h"
#include "transport/recovery/detect/lossdrive/lossdelay.h"
#include "transport/recovery/detect/recovery/lossdetect.h"

/** RFC 9002 A.7: what one step's ACK ranges newly acknowledged in the
 * sent-packet record (wired_srvloop.sent). */
typedef struct {
  u64 largest;      /**< the sample frame's Largest Acknowledged */
  int largest_hit;  /**< 1 once largest was newly acknowledged */
  u64 largest_sent; /**< its send time, ms */
  int eliciting;    /**< 1 once a newly acked packet was ack-eliciting */
} srvrun_rec_acked;

static int  srvrun_rec_in(const sentmeta_pkt* p, u64 lo, u64 hi);
static void srvrun_rec_take(sentmeta* m, usz i, srvrun_rec_acked* a);
static void srvrun_rec_ack_range(
    sentmeta* m, u64 lo, u64 hi, srvrun_rec_acked* a);
static int srvrun_rec_samples(const srvrun_conn* c, const srvrun_rec_acked* a);
static u64 srvrun_rec_ack_delay_us(const srvrun_conn* c);
static u64 srvrun_rec_largest(const wired_srvloop* l);
static int srvrun_rec_eligible(const sentmeta_pkt* p, u64 largest_acked);
static int srvrun_rec_lost(
    const sentmeta_pkt* p, u64 largest_acked, u64 now_us, u64 delay_us);
static void srvrun_rec_arm(srvrun_conn* c, u64 at_us);
static void srvrun_rec_check(srvrun_conn* c, usz i, u64 now_us, u64 delay_us);

/* RFC 9002 6.1.2 / A.10: loss_delay = max(kTimeThreshold *
 * max(smoothed_rtt, latest_rtt), kGranularity), in us. An estimator that
 * was never initialized (rtt_init seeds kInitialRtt, so only a bare
 * zeroed connection has smoothed_rtt 0 without a sample) skips the time
 * threshold instead: 0. */
u64 srvrun_loss_delay_us(const srvrun_conn* c) {
  if (!c->rtt.have_sample && !c->rtt.smoothed_rtt) {
    return 0;
  }
  return lossdrive_loss_delay(
      c->rtt.smoothed_rtt, c->latest_rtt_ms * 1000, RTT_GRANULARITY);
}

/* RFC 9000 18.2: the peer's max_ack_delay (default 25ms), in us. */
u64 srvrun_peer_max_ack_delay_us(const srvrun_conn* c) {
  u64 p1 = c->s.sdrv.peer_max_ack_delay_p1;
  return (p1 ? p1 - 1 : 25) * 1000;
}

/* RFC 9000 19.3: the sample frame's ACK Delay field scaled by the peer's
 * ack_delay_exponent (default 3), in us. */
static u64 srvrun_rec_ack_delay_us(const srvrun_conn* c) {
  u64 p1 = c->s.sdrv.peer_ack_delay_exponent_p1;
  return c->l.ackst.delay_raw << (p1 ? p1 - 1 : 3);
}

static int srvrun_rec_in(const sentmeta_pkt* p, u64 lo, u64 hi) {
  return p->used && p->pn >= lo && p->pn <= hi;
}

/* A.7 DetectAndRemoveAckedPackets for record slot i. */
static void srvrun_rec_take(sentmeta* m, usz i, srvrun_rec_acked* a) {
  a->eliciting |= m->pkts[i].ack_eliciting;
  if (m->pkts[i].pn == a->largest) {
    a->largest_hit  = 1;
    a->largest_sent = m->pkts[i].time_sent;
  }
  sentmeta_reclaim(m, i);
}

static void srvrun_rec_ack_range(
    sentmeta* m, u64 lo, u64 hi, srvrun_rec_acked* a) {
  for (usz i = 0; i < SENTMETA_CAP; i++) {
    if (srvrun_rec_in(&m->pkts[i], lo, hi)) {
      srvrun_rec_take(m, i, a);
    }
  }
}

/* RFC 9002 5.1 / A.7: sample only when the frame's largest acknowledged is
 * newly acknowledged and some newly acknowledged packet is ack-eliciting;
 * RFC 9000 9.4: never from a packet sent before the estimator was reset
 * for a new path (below mig.cc_from_pn). */
static int srvrun_rec_samples(const srvrun_conn* c, const srvrun_rec_acked* a) {
  return a->largest_hit && a->eliciting && a->largest >= c->mig.cc_from_pn;
}

/* The largest Largest Acknowledged among the step's ACK frames -- the
 * highest range end, since each frame's first range ends at its own. */
static u64 srvrun_rec_largest(const wired_srvloop* l) {
  u64 largest = 0;
  for (usz i = 0; i < l->ack_n; i++) {
    largest = u64_max(largest, l->ack_hi[i]);
  }
  return largest;
}

/* RFC 9002 A.7 OnAckReceived over the sent-packet record: drop every newly
 * acknowledged packet (bytes in flight shrink with it) and take this
 * step's one RTT sample, adjusted by the peer's ACK Delay (5.3). */
void srvrun_rec_on_acks(srvrun_conn* c, u64 now_ms) {
  srvrun_rec_acked a = {srvrun_rec_largest(&c->l), 0, 0, 0};
  for (usz i = 0; i < c->l.ack_n; i++) {
    srvrun_rec_ack_range(&c->l.ackst.sent, c->l.ack_lo[i], c->l.ack_hi[i], &a);
  }
  if (srvrun_rec_samples(c, &a)) {
    srvrun_rtt_update(c, now_ms - a.largest_sent, srvrun_rec_ack_delay_us(c));
  }
}

/* A.10: only packets below the largest acknowledged are candidates. */
static int srvrun_rec_eligible(const sentmeta_pkt* p, u64 largest_acked) {
  return p->used && p->pn < largest_acked;
}

/* A.10: past kPacketThreshold, or sent at or before now - loss_delay (a 0
 * delay -- no estimator -- leaves the time threshold out). */
static int srvrun_rec_lost(
    const sentmeta_pkt* p, u64 largest_acked, u64 now_us, u64 delay_us) {
  return loss_by_packet(largest_acked, p->pn) ||
         (delay_us && p->time_sent * 1000 + delay_us <= now_us);
}

/* A.10: loss_time = min over the not-yet-lost of time_sent + loss_delay. */
static void srvrun_rec_arm(srvrun_conn* c, u64 at_us) {
  if (!c->loss_time_us || at_us < c->loss_time_us) {
    c->loss_time_us = at_us;
  }
}

static void srvrun_rec_check(srvrun_conn* c, usz i, u64 now_us, u64 delay_us) {
  const sentmeta_pkt* p = &c->l.ackst.sent.pkts[i];
  if (srvrun_rec_lost(p, c->largest_acked, now_us, delay_us)) {
    sentmeta_reclaim(&c->l.ackst.sent, i);
    return;
  }
  srvrun_rec_arm(c, p->time_sent * 1000 + delay_us);
}

/* RFC 9002 A.10 DetectAndRemoveLostPackets over the sent-packet record:
 * lost packets leave bytes in flight, and the earliest time a remaining
 * candidate could be declared lost arms the loss timer (6.1.2: "a timer
 * SHOULD be set for the remaining time"); 0 disarms it. The send sessions'
 * own pass (srvrun_reap_losses_all) requeues the STREAM data. */
void srvrun_rec_detect(srvrun_conn* c, u64 now_ms) {
  u64 delay_us    = srvrun_loss_delay_us(c);
  c->loss_time_us = 0;
  for (usz i = 0; i < SENTMETA_CAP; i++) {
    if (srvrun_rec_eligible(&c->l.ackst.sent.pkts[i], c->largest_acked)) {
      srvrun_rec_check(c, i, now_ms * 1000, delay_us);
    }
  }
}

/* RFC 9002 2 / 7: bytes in flight -- the send sessions' STREAM slices plus
 * every other in-flight packet the record counts. */
usz srvrun_bytes_in_flight(const srvrun_conn* c) {
  return c->acct_inflight + c->l.ackst.sent.total_in_flight;
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

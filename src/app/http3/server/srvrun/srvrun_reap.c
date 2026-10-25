#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_ecn_note_acked(srvrun_conn* c, u64 hits, u64 newest_ms);
static void srvrun_cc_sample(
    srvrun_conn* c, wired_sendsess* sess, u64 lo, u64 hi, u64 now_ms);
static void srvrun_cc_range(
    srvrun_conn* c, wired_sendsess* sess, u64 lo, u64 hi, u64 now_ms);
static void srvrun_loss_span_add(
    srvrun_loss_span* s, const wired_sendsess_lost_slice* l);

/* Accumulate one range's newly-acked packets into the step's ECN scratch
 * (srvrun_conn.ecn_newly/ecn_sent_ms), before wired_sendsess_ack clears
 * the entries it would count. */
static void srvrun_ecn_note_acked(srvrun_conn* c, u64 hits, u64 newest_ms) {
  c->ecn_newly += hits;
  if (newest_ms > c->ecn_sent_ms) {
    c->ecn_sent_ms = newest_ms;
  }
}

/* The RTT, ECN and congestion inputs of the packets [lo, hi] acked. */
static void srvrun_cc_sample(
    srvrun_conn* c, wired_sendsess* sess, u64 lo, u64 hi, u64 now_ms) {
  u64 newest = 0;
  usz bytes;
  if (lo > hi) {
    return;
  }
  bytes = wired_sendsess_peek_ack(sess, lo, hi, &newest);
  srvrun_ecn_note_acked(c, srvrun_range_hits(sess, lo, hi), newest);
  if (bytes) {
    srvrun_rtt_note(c, now_ms - newest);
    srvrun_hystart_range(c, sess, lo, hi, now_ms);
    cc_on_ack(&c->cc, srvrun_css_acked(c, bytes), newest, now_ms);
  }
}

/* RFC 9000 9.4: packets sent before the congestion controller and RTT
 * estimator were reset for a new path (below cc_from_pn) are acknowledged
 * but feed neither. */
static void srvrun_cc_range(
    srvrun_conn* c, wired_sendsess* sess, u64 lo, u64 hi, u64 now_ms) {
  if (!srvrun_range_hits(sess, lo, hi)) {
    return;
  }
  srvrun_cc_sample(c, sess, u64_max(lo, c->mig.cc_from_pn), hi, now_ms);
  wired_sendsess_ack(sess, lo, hi);
}

static void srvrun_loss_span_add(
    srvrun_loss_span* s, const wired_sendsess_lost_slice* l) {
  s->newest_ms = u64_max(s->newest_ms, l->sent_ms);
  s->oldest_ms = u64_min(s->oldest_ms, l->sent_ms);
  s->lo_pn     = u64_min(s->lo_pn, l->pn);
  s->hi_pn     = u64_max(s->hi_pn, l->pn);
}

/* Threshold pass over sess's log: requeue losses, log each lost packet. The
 * congestion-window shrink (cc_on_loss) is applied once per step by
 * the caller (srvrun_feed_acks), not here, so a loss on several concurrent
 * responses in the same step still only shrinks the connection's one
 * window once. span accumulates the declared losses' extent
 * (srvrun_loss_span). */
usz srvrun_reap_losses(
    const srvrun_cfg*  cfg,
    const srvrun_conn* c,
    wired_sendsess*    sess,
    u64                stream_id,
    u64                now_ms,
    srvrun_loss_span*  span) {
  wired_sendsess_lost_slice lost[WIRED_SENDSESS_LOG];
  usz                       n = wired_sendsess_detect_lost(
      sess, c->largest_acked, now_ms, c->rtt.smoothed_rtt, lost,
      WIRED_SENDSESS_LOG);
  srvrun_qlog_lost(cfg, c, now_ms, stream_id, lost, n);
  for (usz i = 0; i < n; i++) {
    srvrun_loss_span_add(span, &lost[i]);
  }
  return n;
}

/* Ack/cc accounting for one range on every in-use wtsend session. Loss
 * reaping deliberately does NOT happen here -- see srvrun_feed_acks. */
void srvrun_ack_range_wt(srvrun_conn* c, u64 lo, u64 hi, u64 now_ms) {
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++) {
    if (c->wtsend[i].in_use) {
      srvrun_cc_range(c, &c->wtsend[i].sess, lo, hi, now_ms);
    }
  }
}

/* The resp[] half of the ACK-range broadcast, mirroring the wtsend loop. */
void srvrun_ack_range_resps(srvrun_conn* c, u64 lo, u64 hi, u64 now_ms) {
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++) {
    if (c->resp[i].in_use) {
      srvrun_cc_range(c, &c->resp[i].sess, lo, hi, now_ms);
    }
  }
}

/* One loss pass over every in-use wtsend session against the connection's
 * ONE largest_acked (RFC 9002 6.1.1); the slot's stream_id is only for the
 * loss records' qlog attribution (RFC 9000 19.8). */
usz srvrun_reap_losses_wt(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 now_ms, srvrun_loss_span* span) {
  usz lost = 0;
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++) {
    if (c->wtsend[i].in_use) {
      lost += srvrun_reap_losses(
          cfg, c, &c->wtsend[i].sess, c->wtsend[i].stream_id, now_ms, span);
    }
  }
  return lost;
}

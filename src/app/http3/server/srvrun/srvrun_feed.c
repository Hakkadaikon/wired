#include "app/http3/server/srvrun/srvrun_impl.h"

static usz srvrun_reap_losses_resps(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 now_ms, srvrun_loss_span* span);
static int srvrun_pmtu_probe_in_range(const srvrun_conn* c, u64 lo, u64 hi);
static int srvrun_acked_between(const srvrun_conn* c, u64 lo, u64 hi);

/* The resp[] half of the loss pass. */
static usz srvrun_reap_losses_resps(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 now_ms, srvrun_loss_span* span) {
  usz lost = 0;
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++) {
    if (c->resp[i].in_use) {
      lost += srvrun_reap_losses(
          cfg, c, &c->resp[i].sess, c->resp[i].stream_id, now_ms, span);
    }
  }
  return lost;
}

/* The whole-connection loss pass: every in-use send session, wtsend and
 * resp[] alike. Runs once per srvrun_feed_acks batch, never per range. */
usz srvrun_reap_losses_all(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 now_ms, srvrun_loss_span* span) {
  return srvrun_reap_losses_wt(cfg, c, now_ms, span) +
         srvrun_reap_losses_resps(cfg, c, now_ms, span);
}

/* 1 if [lo,hi] covers c's one outstanding DPLPMTUD probe pn -- the probe
 * lives outside every resp[]/wtsend[] send-session log (srvrun_conn's own
 * pmtu_probe_pn doc), so this is a separate branch from the range-based
 * loss detection above, not a change to it. */
static int srvrun_pmtu_probe_in_range(const srvrun_conn* c, u64 lo, u64 hi) {
  return srvrun_pmtu_probe_outstanding(c) && c->pmtu_probe_pn >= lo &&
         c->pmtu_probe_pn <= hi;
}

/* RFC 8899 5.1.3: an acked probe raises the validated PMTU (pmtu_on_ack)
 * and resolves the outstanding tracking, letting the next opportunity start
 * a new probe. Entirely independent of the resp[]/wtsend[] ACK accounting
 * above -- a probe's pn belongs to neither log. */
void srvrun_pmtu_reap_ack(srvrun_conn* c, u64 lo, u64 hi) {
  if (!srvrun_pmtu_probe_in_range(c, lo, hi)) {
    return;
  }
  pmtu_on_ack(&c->pmtu, c->pmtu_probe_size);
  srvrun_pmtu_probe_clear(c);
}

/* Broadcast one ACK range's accounting to every in-flight send session
 * (resp[] and wtsend alike), after raising the connection's shared
 * largest_acked (RFC 9002 6.1.1: one packet number space, one
 * largest_acked -- never regresses). Accounting only -- no loss pass. */
void srvrun_feed_ack_range(srvrun_conn* c, u64 lo, u64 hi, u64 now_ms) {
  if (hi > c->largest_acked) {
    c->largest_acked = hi;
  }
  srvrun_ack_range_wt(c, lo, hi, now_ms);
  srvrun_ack_range_resps(c, lo, hi, now_ms);
  srvrun_rst_ack(c, lo, hi);
  srvrun_pmtu_reap_ack(c, lo, hi);
}

/* Consume a step's ACK ranges, THEN run one loss pass over the whole
 * connection. The two-phase order is load-bearing in both directions:
 * (a) reaping per range mis-fires -- an ACK frame's ranges arrive
 * largest-first, so a reap right after range 0 sees the lower ranges'
 * packets as unacked-behind-largest and spuriously requeues them (a real
 * quic-go client's ACKs for streams 4/8 once re-sent ~35KB of stream 0's
 * already-delivered body this way); (b) reaping only sessions the peer
 * has acked leaves a one-shot round whose only packet was dropped -- so
 * no session-local ACK can ever arrive -- undeclared for tens of seconds
 * (RFC 9002 6.1's "sent prior to an acknowledged packet" is about the
 * connection's packet number space, not one session's own ACK history;
 * the s3-voice-loss qlog caught exactly this on chat relay streams). */
/* RFC 9000 13.4.2: validate and consume this step's ECN feedback, only
 * when the step raised largest_acked (13.4.2.1: an endpoint MUST NOT fail
 * validation on a reordered ACK that does not). Every packet this server
 * sends is ECT(0)-marked (wired_udp_ect0_enable on the listen socket), so
 * l.tx_pn -- 1-RTT packets sealed so far -- bounds the ECT(0) counts the
 * peer can truthfully report, and the packets the step newly acked
 * (ecn_newly) bound the increase from below. A step whose ACKs carried no
 * ECN counts while marked packets are out fails validation instead
 * (13.4.2.1: the path or peer dropped the marks). A failed validation
 * also stops marking this connection's packets (srvrun_ecn_unmarked). */
void srvrun_feed_ecn(srvrun_conn* c, u64 largest_before, u64 now_ms) {
  if (c->largest_acked <= largest_before) {
    return;
  }
  if (!c->l.ecn_ack_seen) {
    ecn_track_on_missing(&c->ecn, c->l.tx_pn);
    return;
  }
  ecn_report r = {
      {c->l.ecn_ack_ce, c->l.ecn_ack_ect0},
      c->l.ecn_ack_ect1,
      c->l.tx_pn,
      c->ecn_newly};
  ecn_track_on_counts(&c->ecn, &c->cc, &r, c->ecn_sent_ms, now_ms);
}

/* 1 if this step's ACK frame acknowledges some pn strictly between lo and
 * hi -- or may have: a full ack_lo[] array means ranges past it (the lowest
 * pns, srvloop_push_ack / ack_decode keep only the first 32) were dropped
 * unseen, so the answer is unknown and counted as a hit. */
static int srvrun_acked_between(const srvrun_conn* c, u64 lo, u64 hi) {
  int hit = c->l.ack_n >= sizeof c->l.ack_lo / sizeof c->l.ack_lo[0];
  for (usz i = 0; i < c->l.ack_n; i++) {
    hit |= c->l.ack_lo[i] < hi && c->l.ack_hi[i] > lo;
  }
  return hit;
}

/* RFC 9002 7.6.2: no packet sent between the batch's oldest and newest
 * lost ones was acknowledged. Every earlier step's ACK is at most
 * largest_before, so requiring that below lo_pn leaves only this step's
 * own ranges to check. ponytail: a period overlapping an earlier step's
 * ACK is never declared (the SHOULD is missed, never falsely met); keep a
 * per-pn acked record if that ever matters. */
int srvrun_loss_unbroken(
    const srvrun_conn* c, const srvrun_loss_span* s, u64 largest_before) {
  return largest_before < s->lo_pn &&
         !srvrun_acked_between(c, s->lo_pn, s->hi_pn);
}

/* RFC 9002 7.6.2: the period must start after the first RTT sample and
 * span (smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay) x
 * kPersistentCongestionThreshold. Two distinct packets are implied: the
 * PTO is at least kGranularity, so a zero span never qualifies. */
int srvrun_loss_long(const srvrun_conn* c, const srvrun_loss_span* s) {
  return c->rtt.have_sample && s->lo_pn >= c->rtt_from_pn &&
         cc_persistent(
             (s->newest_ms - s->oldest_ms) * 1000,
             rtt_pto(&c->rtt, srvrun_peer_max_ack_delay_us(c)));
}

#include "app/http3/server/srvrun/srvrun_impl.h"

static u64  srvrun_pace_rate_raw(const srvrun_conn* c);
static u64  srvrun_pace_rate(const srvrun_conn* c);
static u64  srvrun_pace_new_tokens(const srvrun_conn* c, u64 now_ms);
static int  srvrun_hystart_paces(const srvrun_conn* c);
static void srvrun_hystart_ack(srvrun_conn* c, u64 pn, u64 sent_ms, u64 now);

/* Bytes per ms the pacer refills at: BBR paces at its own model's
 * pacing_gain% x btl_bw (falling back to the generic formula until the
 * first bandwidth sample); Reno/Cubic at RFC 9002 7.7's 1.25 * cwnd /
 * srtt. Callers guarantee srtt_ms != 0. */
static u64 srvrun_pace_rate_raw(const srvrun_conn* c) {
  if (c->cc.algo == CC_ALGO_BBR && c->cc.bbr.btl_bw) {
    return bbr_pacing_gain_pct(&c->cc.bbr) * c->cc.bbr.btl_bw / 100;
  }
  return 5 * c->cc.cwnd / (4 * c->srtt_ms);
}

/* Floored at 1 B/ms so a degenerate estimate can never stall the refill
 * entirely (the tokens would otherwise never accumulate again). */
static u64 srvrun_pace_rate(const srvrun_conn* c) {
  return u64_max(srvrun_pace_rate_raw(c), 1);
}

/* The uncapped balance after refilling for the wall time since the last
 * refill. pace_refill_ms == 0 means "never refilled": a full bucket, so the
 * very first paced pass is not stalled (real monotonic now_ms is never 0 --
 * only a fresh connection carries the 0 stamp). */
static u64 srvrun_pace_new_tokens(const srvrun_conn* c, u64 now_ms) {
  if (!c->pace_refill_ms) {
    return SRVRUN_PACE_BURST;
  }
  return c->pace_tokens + (now_ms - c->pace_refill_ms) * srvrun_pace_rate(c);
}

/* Advance the token bucket by the wall time since the last refill, capped
 * at the burst ceiling. Once per pump pass (srvrun_pump_sess) -- within a
 * pass now_ms is frozen, so the pass can never send more than one bucket.
 */
void srvrun_pace_refill(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  u64 t;
  if (!c->srtt_ms) {
    return; /* unpaced until the first RTT sample */
  }
  t                 = srvrun_pace_new_tokens(c, ctx->now_ms);
  c->pace_tokens    = t > SRVRUN_PACE_BURST ? SRVRUN_PACE_BURST : t;
  c->pace_refill_ms = ctx->now_ms;
}

/* Spend bytes from the bucket (clamped at zero -- srvrun_pace_ok's > 0
 * gate deliberately allows a one-slice overdraft). */
void srvrun_pace_charge(srvrun_conn* c, usz bytes) {
  c->pace_tokens = c->pace_tokens > bytes ? c->pace_tokens - bytes : 0;
}

/* 1 when pacing allows a send now: unpaced until the first RTT sample; in
 * the sub-poll-tick regime (srvrun_pace_within_poll_tick) the token bucket
 * decides -- the ACK-clocked steps refill it, so throughput follows the
 * pacing rate instead of the 25ms poll cadence, while a burst stays under
 * the bucket and cannot overflow a shallow bottleneck queue; past one poll
 * tick, the absolute next_send_ms deadline as before. */
int srvrun_pace_ok(const srvrun_step_ctx* ctx, const srvrun_conn* c) {
  if (!c->srtt_ms) {
    return 1;
  }
  if (srvrun_pace_within_poll_tick(c)) {
    return c->pace_tokens > 0;
  }
  return ctx->now_ms >= c->next_send_ms;
}

/* 1 if NewReno's pacing interval is under one poll-loop tick (RFC 9002 7.7
 * intends smoothing bursts, not capping throughput): srvrun has no timer-
 * driven send loop -- srvrun_pump_sess only ever runs from srvrun_sess_
 * on_step (a received datagram) or srvrun_pto_slot (the SRVRUN_PTO_MS=25ms
 * poll tick), so a real send opportunity is at best SRVRUN_PTO_MS away.
 * Deferring a send to next_send_ms when the theoretical gap is already
 * shorter than that just pins the whole connection to the poll cadence
 * instead of the pacing rate -- observed pinning "response slice sent" to
 * a ~25-30ms cadence against a real quic-go client even with cwnd grown
 * past 4MB and zero loss, an effective throughput far under the link's real
 * capacity (interop goodput timing out at 60s). Once the interval grows
 * past SRVRUN_PTO_MS, deferring is real: a later poll tick or the next ACK
 * will still be there to pick the send back up, and pacing spreads it
 * genuinely. BBR is ALWAYS token-gated: pacing at pacing_gain x btl_bw is
 * its core mechanism (srvrun_pace_rate_raw), and the next_send_ms deferral
 * would pin it to the poll cadence exactly like the pre-token-bucket
 * regression this comment records. */
int srvrun_pace_within_poll_tick(const srvrun_conn* c) {
  return c->cc.algo == CC_ALGO_BBR ||
         pacing_interval(c->srtt_ms, c->cc.cwnd, MAX_DATAGRAM) < SRVRUN_PTO_MS;
}

/* Schedule the next paced send (RFC 9002 7.7: ~1.25x cwnd/srtt rate) --
 * a no-op (send stays due now) while the real interval already fits inside
 * one poll tick, see srvrun_pace_within_poll_tick. */
void srvrun_pace_next(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  if (srvrun_pace_within_poll_tick(c)) {
    return;
  }
  c->next_send_ms =
      ctx->now_ms + cc_pacing_ms(&c->cc, c->srtt_ms, MAX_DATAGRAM);
}

/* 1 while HyStart++ governs this connection's growth: the INITIAL
 * Reno/Cubic slow start only (RFC 9406 4.3) -- ssthresh is still its
 * initial infinity, so no loss and no HyStart++ exit has happened yet. BBR's
 * ack bytes feed its own model, never slow-start growth. */
static int srvrun_hystart_paces(const srvrun_conn* c) {
  return c->cc.algo != CC_ALGO_BBR && c->cc.ssthresh == ~(u64)0;
}

/* The bytes to credit cc_on_ack with: HyStart++'s CSS growth divisor
 * (hystart_acked) while Reno/Cubic are still in slow start. */
u64 srvrun_css_acked(const srvrun_conn* c, u64 bytes) {
  return srvrun_hystart_paces(c) ? hystart_acked(&c->hs, bytes) : bytes;
}

/* Feed one acked packet's sample to the slow-start exit detector (RFC 9406,
 * which explicitly samples every ACKed packet in a round, not just the
 * newest); on the verdict, end slow start by dropping ssthresh to the
 * current window. Round boundary: the next pn to be sent. Does NOT touch
 * the RTT estimator -- see srvrun_hystart_range's comment for why. */
static void srvrun_hystart_ack(srvrun_conn* c, u64 pn, u64 sent_ms, u64 now) {
  if (!srvrun_hystart_paces(c)) {
    return;
  }
  if (hystart_sample(&c->hs, now - sent_ms, pn, c->l.tx_pn)) {
    c->cc.ssthresh = c->cc.cwnd;
  }
}

/* Feed every in-flight packet an ACK range covers to the hystart detector
 * (RFC 9406 intends every sample in the round, unlike RTT estimation) --
 * the RTT estimator itself is fed separately, once, from the range's newest
 * send time (RFC 9002 5.1: "an endpoint... SHOULD generate an RTT sample
 * using only the largest acknowledged packet in the received ACK frame").
 * Feeding every hit here fed the SAME range's older, already-in-flight-a-
 * while slices as separate samples too -- under round-robin pumping
 * (srvrun_pump_round) a slot's own slices spread further apart in real send
 * time than under the old drain-then-next order, so those older samples'
 * inflated (now - sent_ms) dragged smoothed_rtt further from the true RTT
 * every ACK, observed as srtt climbing from ~36ms to ~55ms over a run whose
 * simulated RTT never changed. */
void srvrun_hystart_range(
    srvrun_conn* c, const wired_sendsess* sess, u64 lo, u64 hi, u64 now) {
  for (usz i = 0; i < sess->log_hi; i++) {
    const wired_sent_slice* e = &sess->log[i];
    if (wired_sendsess_covered(e, lo, hi)) {
      srvrun_hystart_ack(c, e->pn, e->sent_ms, now);
    }
  }
}

/* Credit one ACK range against r's log to the congestion controller before
 * consuming it (RFC 9002 7.3.2: growth per acked bytes; the newest send
 * time among the hits drives recovery exit). A range is broadcast to every
 * resp[] slot, and wired_sendsess_ack only clears the log entries that hit
 * ITS OWN log (sendsess.c) -- but it also unconditionally raises
 * largest_acked to the range's hi, even when hi belongs to another slot's
 * pn (pn is a single monotonic per-connection space, so a broadcast range
 * routinely names pns this slot never sent). That falsely advances this
 * slot's packet-loss threshold (RFC 9002 6.1.1) and requeues in-flight
 * slices that were never actually lost. Only forward the range when it
 * actually hits something in r's own log. */
/* How many of sess's own in-flight log entries [lo, hi] covers, regardless
 * of byte length -- wired_sendsess_peek_ack's own bytes==0 return (a
 * bare-FIN round's synthetic 0-byte slice, srvrun_pump_wt_fin_ only) must
 * not be mistaken for "nothing of ours was hit" the way it legitimately is
 * for a resp[]/wtsend slot with no in-flight data at all: a 0-byte slice
 * still needs its own wired_sendsess_ack, or its log entry never clears
 * and the slot never reaps (wired_sendsess_done keeps seeing it as pending
 * forever). The count also feeds RFC 9000 13.4.2.1's ECN bound. */
u64 srvrun_range_hits(const wired_sendsess* sess, u64 lo, u64 hi) {
  u64 n = 0;
  for (usz i = 0; i < sess->log_hi; i++) {
    n += (u64)wired_sendsess_covered(&sess->log[i], lo, hi);
  }
  return n;
}

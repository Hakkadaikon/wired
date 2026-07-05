#include "transport/recovery/congestion/cc/cc.h"

#include "common/bytes/util/num.h"
#include "transport/recovery/congestion/cc/cubic.h"
#include "transport/recovery/congestion/cc/pacing.h"

void quic_cc_init(quic_cc* c) { quic_cc_init_algo(c, QUIC_CC_ALGO_NEWRENO); }

void quic_cc_init_algo(quic_cc* c, int algo) {
  c->cwnd           = QUIC_CC_INIT_WINDOW;
  c->ssthresh       = ~(u64)0; /* "infinite" until the first loss */
  c->in_recovery    = 0;
  c->recovery_start = 0;
  c->algo           = algo;
  c->w_max_seg      = 0;
  c->k_ms           = 0;
  c->epoch_ms       = 0;
  c->round_bytes    = 0;
  c->round_start_ms = 0;
  quic_bbr_init(&c->bbr);
}

/* Grow the window: exponential in slow start, linear in avoidance. */
static void grow(quic_cc* c, u64 acked) {
  u64 inc = (c->cwnd < c->ssthresh)
                ? acked                                     /* slow start */
                : (u64)QUIC_MAX_DATAGRAM * acked / c->cwnd; /* avoidance */
  c->cwnd += inc;
}

/* Leave recovery once an ack arrives for a packet sent after it began. */
static void maybe_exit_recovery(quic_cc* c, u64 sent_time) {
  if (c->in_recovery && sent_time > c->recovery_start) c->in_recovery = 0;
}

/* RFC 9438 4.1: lift cwnd onto the cubic curve at `now`; before the first
 * loss (no epoch) CUBIC slow-starts like NewReno. */
static void grow_cubic(quic_cc* c, u64 acked, u64 now) {
  u64 target;
  if (!c->w_max_seg) {
    grow(c, acked);
    return;
  }
  target = quic_cubic_w(now - c->epoch_ms, c->k_ms, c->w_max_seg) *
           QUIC_MAX_DATAGRAM;
  if (target > c->cwnd) c->cwnd = target;
}

/* BBR: acks only feed the samplers; cwnd moves in quic_cc_bbr_tick. */
static void feed_bbr(quic_cc* c, u64 acked, u64 sent_time, u64 now) {
  quic_bbr_on_rtt(&c->bbr, now - sent_time, now);
  c->round_bytes += acked;
}

static void grow_algo(quic_cc* c, u64 acked, u64 now) {
  if (c->algo == QUIC_CC_ALGO_CUBIC) {
    grow_cubic(c, acked, now);
    return;
  }
  grow(c, acked);
}

void quic_cc_on_ack(quic_cc* c, u64 acked, u64 sent_time, u64 now) {
  if (c->algo == QUIC_CC_ALGO_BBR) {
    feed_bbr(c, acked, sent_time, now);
    return;
  }
  maybe_exit_recovery(c, sent_time);
  if (!c->in_recovery) grow_algo(c, acked, now);
}

/* RFC 9438 4.6/4.7: remember W_max (fast convergence), re-anchor the cubic
 * epoch at this loss, shrink by beta_cubic (0.7). */
static u64 loss_window_cubic(quic_cc* c, u64 now) {
  u64 w_seg    = c->cwnd / QUIC_MAX_DATAGRAM;
  c->w_max_seg = quic_cubic_wmax_fastconv(w_seg, c->w_max_seg);
  c->k_ms      = quic_cubic_k_ms(c->w_max_seg);
  c->epoch_ms  = now;
  return quic_u64_max(c->cwnd * 7 / 10, QUIC_CC_MIN_WINDOW);
}

static u64 loss_window(quic_cc* c, u64 now) {
  if (c->algo == QUIC_CC_ALGO_CUBIC) return loss_window_cubic(c, now);
  return quic_u64_max(c->cwnd / 2, QUIC_CC_MIN_WINDOW);
}

void quic_cc_on_loss(quic_cc* c, u64 sent_time, u64 now) {
  if (c->in_recovery || sent_time < c->recovery_start) return; /* once/window */
  c->ssthresh       = loss_window(c, now);
  c->cwnd           = c->ssthresh;
  c->in_recovery    = 1;
  c->recovery_start = now;
}

void quic_cc_on_persistent(quic_cc* c) { c->cwnd = QUIC_CC_MIN_WINDOW; }

/* The bandwidth-delay product in bytes (btl_bw B/ms x rtprop ms). */
static u64 bbr_bdp(const quic_cc* c) {
  return c->bbr.btl_bw * c->bbr.rtprop_ms;
}

/* Close the sample round once at least one rtprop (min 1ms) has elapsed. */
static void bbr_round_close(quic_cc* c, u64 now_ms) {
  u64 span = now_ms - c->round_start_ms;
  u64 need = quic_u64_max(c->bbr.rtprop_ms, 1);
  if (span < need || !c->round_bytes) return;
  quic_bbr_on_round(&c->bbr, c->round_bytes / span);
  c->round_bytes    = 0;
  c->round_start_ms = now_ms;
}

/* cwnd = cwnd_gain x BDP once the estimators have data. */
static void bbr_set_cwnd(quic_cc* c) {
  u64 bdp = bbr_bdp(c);
  if (!bdp) return;
  c->cwnd = quic_u64_max(
      quic_bbr_cwnd_gain_pct(&c->bbr) * bdp / 100, QUIC_CC_MIN_WINDOW);
}

void quic_cc_bbr_tick(quic_cc* c, u64 inflight_bytes, u64 now_ms) {
  if (c->algo != QUIC_CC_ALGO_BBR) return;
  bbr_round_close(c, now_ms);
  quic_bbr_drained(&c->bbr, inflight_bytes <= bbr_bdp(c));
  quic_bbr_cycle_tick(&c->bbr);
  if (!quic_bbr_check_probe_rtt(&c->bbr, now_ms))
    quic_bbr_probe_rtt_exit(&c->bbr, now_ms);
  bbr_set_cwnd(c);
}

/* BBR rate: mtu / (pacing_gain x btl_bw), floored at 1ms once bw is known. */
static u64 bbr_pacing_ms(const quic_cc* c, u64 mtu) {
  u64 rate = quic_bbr_pacing_gain_pct(&c->bbr) * c->bbr.btl_bw / 100;
  if (!rate) return 0;
  return quic_u64_max(mtu / rate, 1);
}

u64 quic_cc_pacing_ms(const quic_cc* c, u64 srtt_ms, u64 mtu) {
  if (c->algo == QUIC_CC_ALGO_BBR) return bbr_pacing_ms(c, mtu);
  return quic_pacing_interval(srtt_ms, c->cwnd, mtu);
}

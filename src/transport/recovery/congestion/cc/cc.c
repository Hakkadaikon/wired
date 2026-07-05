#include "transport/recovery/congestion/cc/cc.h"

#include "common/bytes/util/num.h"
#include "transport/recovery/congestion/cc/cubic.h"

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

static void grow_algo(quic_cc* c, u64 acked, u64 now) {
  if (c->algo == QUIC_CC_ALGO_CUBIC) {
    grow_cubic(c, acked, now);
    return;
  }
  grow(c, acked);
}

void quic_cc_on_ack(quic_cc* c, u64 acked, u64 sent_time, u64 now) {
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

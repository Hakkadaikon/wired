#include "transport/recovery/congestion/cc/cc.h"

#include "common/bytes/util/num.h"

void quic_cc_init(quic_cc *c) {
  c->cwnd           = QUIC_CC_INIT_WINDOW;
  c->ssthresh       = ~(u64)0; /* "infinite" until the first loss */
  c->in_recovery    = 0;
  c->recovery_start = 0;
}

/* Grow the window: exponential in slow start, linear in avoidance. */
static void grow(quic_cc *c, u64 acked) {
  u64 inc = (c->cwnd < c->ssthresh)
                ? acked                                     /* slow start */
                : (u64)QUIC_MAX_DATAGRAM * acked / c->cwnd; /* avoidance */
  c->cwnd += inc;
}

/* Leave recovery once an ack arrives for a packet sent after it began. */
static void maybe_exit_recovery(quic_cc *c, u64 sent_time) {
  if (c->in_recovery && sent_time > c->recovery_start) c->in_recovery = 0;
}

void quic_cc_on_ack(quic_cc *c, u64 acked, u64 sent_time) {
  maybe_exit_recovery(c, sent_time);
  if (!c->in_recovery) grow(c, acked);
}

void quic_cc_on_loss(quic_cc *c, u64 sent_time, u64 now) {
  if (c->in_recovery || sent_time < c->recovery_start) return; /* once/window */
  c->ssthresh       = quic_u64_max(c->cwnd / 2, QUIC_CC_MIN_WINDOW);
  c->cwnd           = c->ssthresh;
  c->in_recovery    = 1;
  c->recovery_start = now;
}

void quic_cc_on_persistent(quic_cc *c) { c->cwnd = QUIC_CC_MIN_WINDOW; }

#include "transport/recovery/congestion/cc/ccloss.h"

#include "common/bytes/util/num.h"
#include "transport/recovery/congestion/cc/cc.h"
#include "transport/recovery/congestion/cc/cubic.h"

int cc_in_recovery(u64 sent_time, u64 recovery_start) {
  return sent_time <= recovery_start;
}

/* RFC 9002 B.8: collapse to kMinimumWindow and clear the recovery period
 * (congestion_recovery_start_time = 0). BBR sizes cwnd from its own model
 * (bbr_set_cwnd), so it is left alone. */
void cc_on_persistent(cc* c) {
  if (c->algo == CC_ALGO_BBR) {
    return;
  }
  c->cwnd           = CC_MIN_WINDOW;
  c->w_est          = CC_MIN_WINDOW; /* RFC 9438 4.3: restart from here */
  c->in_recovery    = 0;
  c->recovery_start = 0;
}

/* RFC 9438 4.6/4.7: remember W_max (fast convergence), re-anchor the cubic
 * epoch at this loss, shrink by beta_cubic (0.7). */
static u64 loss_window_cubic(cc* c, u64 now) {
  u64 w_seg     = c->cwnd / MAX_DATAGRAM;
  c->w_max_seg  = cubic_wmax_fastconv(w_seg, c->w_max_seg);
  c->k_ms       = cubic_k_ms(c->w_max_seg);
  c->epoch_ms   = now;
  c->cwnd_prior = c->cwnd;
  c->w_est      = u64_max(c->cwnd * 7 / 10, CC_MIN_WINDOW); /* cwnd_epoch */
  return c->w_est;
}

static u64 loss_window(cc* c, u64 now) {
  if (c->algo == CC_ALGO_CUBIC) {
    return loss_window_cubic(c, now);
  }
  return u64_max(c->cwnd / 2, CC_MIN_WINDOW);
}

/* RFC 9002 B.5 InCongestionRecovery: sent at or before the current period
 * began (recovery_start 0: no period, B.8). */
static int cc_in_period(const cc* c, u64 sent_time) {
  return c->recovery_start && cc_in_recovery(sent_time, c->recovery_start);
}

void cc_on_loss(cc* c, u64 sent_time, u64 now) {
  if (c->in_recovery || cc_in_period(c, sent_time)) {
    return; /* once/window */
  }
  c->ssthresh       = loss_window(c, now);
  c->cwnd           = c->ssthresh;
  c->in_recovery    = 1;
  c->recovery_start = now;
}

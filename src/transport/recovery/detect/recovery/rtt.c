#include "transport/recovery/detect/recovery/rtt.h"

#include "common/bytes/util/num.h"

void quic_rtt_init(quic_rtt *r) {
  r->min_rtt      = 0;
  r->smoothed_rtt = QUIC_RTT_INITIAL_US;
  r->rttvar       = QUIC_RTT_INITIAL_US / 2;
  r->have_sample  = 0;
}

/* First sample seeds the estimator directly (RFC 9002 5.2). */
static void first_sample(quic_rtt *r, u64 latest) {
  r->min_rtt      = latest;
  r->smoothed_rtt = latest;
  r->rttvar       = latest / 2;
  r->have_sample  = 1;
}

/* adjusted_rtt = latest - ack_delay when that stays above min_rtt. */
static u64 adjust(const quic_rtt *r, u64 latest, u64 ack_delay) {
  return (latest >= r->min_rtt + ack_delay) ? latest - ack_delay : latest;
}

/* Subsequent samples: EWMA with 1/8 and 1/4 weights (RFC 9002 5.3). */
static void next_sample(quic_rtt *r, u64 latest, u64 ack_delay) {
  u64 adjusted    = adjust(r, latest, ack_delay);
  u64 var_sample  = quic_u64_absdiff(r->smoothed_rtt, adjusted);
  r->min_rtt      = quic_u64_min(r->min_rtt, latest);
  r->rttvar       = (3 * r->rttvar + var_sample) / 4;
  r->smoothed_rtt = (7 * r->smoothed_rtt + adjusted) / 8;
}

void quic_rtt_sample(quic_rtt *r, u64 latest_rtt, u64 ack_delay) {
  if (!r->have_sample)
    first_sample(r, latest_rtt);
  else
    next_sample(r, latest_rtt, ack_delay);
}

u64 quic_rtt_pto(const quic_rtt *r, u64 max_ack_delay) {
  u64 var = quic_u64_max(4 * r->rttvar, QUIC_RTT_GRANULARITY);
  return r->smoothed_rtt + var + max_ack_delay;
}

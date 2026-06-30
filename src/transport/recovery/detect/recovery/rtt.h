#ifndef QUIC_RECOVERY_RTT_H
#define QUIC_RECOVERY_RTT_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 5: RTT estimation. Times are in microseconds. */

#define QUIC_RTT_INITIAL_US 333000 /* kInitialRtt = 333ms */
#define QUIC_RTT_GRANULARITY 1000  /* kGranularity = 1ms */

typedef struct {
  u64 min_rtt;
  u64 smoothed_rtt;
  u64 rttvar;
  int have_sample;
} quic_rtt;

void quic_rtt_init(quic_rtt *r);

/* Fold one RTT sample (latest_rtt, ack_delay) into the estimator. */
void quic_rtt_sample(quic_rtt *r, u64 latest_rtt, u64 ack_delay);

/* PTO = smoothed_rtt + max(4*rttvar, granularity) + max_ack_delay. */
u64 quic_rtt_pto(const quic_rtt *r, u64 max_ack_delay);

#endif

#ifndef RECOVERY_RTT_H
#define RECOVERY_RTT_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 5: RTT estimation. Times are in microseconds. */

#define RTT_INITIAL_US 333000 /* kInitialRtt = 333ms */
#define RTT_GRANULARITY 1000  /* kGranularity = 1ms */

typedef struct {
  u64 min_rtt;
  u64 smoothed_rtt;
  u64 rttvar;
  int have_sample;
} rtt;

void rtt_init(rtt* r);

/* Fold one RTT sample (latest_rtt, ack_delay) into the estimator.
 * RFC 9002 5.3: max_ack_delay is ignored until handshake_confirmed is set,
 * after which ack_delay is clamped to the lesser of itself and
 * max_ack_delay (9002-015, 9002-016). */
void rtt_sample(
    rtt* r,
    u64  latest_rtt,
    u64  ack_delay,
    u64  max_ack_delay,
    int  handshake_confirmed);

/* PTO = smoothed_rtt + max(4*rttvar, granularity) + max_ack_delay. */
u64 rtt_pto(const rtt* r, u64 max_ack_delay);

/* RFC 9002 5.2: once persistent congestion is established, set min_rtt to
 * the newest RTT sample. Avoids repeatedly declaring persistent congestion
 * when the path RTT has genuinely increased (9002-011). */
void rtt_on_persistent(rtt* r, u64 latest_rtt);

#endif

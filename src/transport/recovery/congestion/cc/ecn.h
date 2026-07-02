#ifndef QUIC_CC_ECN_H
#define QUIC_CC_ECN_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 7.1.2: ECN counts must increase monotonically; a CE increase
 * signals congestion. Counts are cumulative per-path. */

/* Cumulative ECN counts (CE and ECT(0)) at one point in time. */
typedef struct {
  u64 ce;
  u64 ect0;
} quic_ecn_counts;

/* 1 if both CE and ECT(0) counts did not decrease, else 0. */
int quic_ecn_counts_valid(quic_ecn_counts prev, quic_ecn_counts next);

/* 1 if the CE count increased. */
int quic_ecn_ce_increased(u64 prev_ce, u64 new_ce);

#endif

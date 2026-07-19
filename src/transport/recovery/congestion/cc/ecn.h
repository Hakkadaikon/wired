#ifndef QUIC_CC_ECN_H
#define QUIC_CC_ECN_H

#include "common/platform/sys/syscall.h"
#include "transport/recovery/congestion/cc/cc.h"

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

/* RFC 9002 7.1.2: "An increase in the CE count is treated as one instance of
 * congestion detection and is handled as if the endpoint had detected a
 * packet loss" -- when the CE count rose since prev_ce, apply the same
 * window reduction quic_cc_on_loss uses (never twice for one recovery
 * period, same in_recovery/recovery_start gating as an ordinary loss). A
 * no-op when the CE count did not increase. */
void quic_ecn_on_ce_increase(
    quic_cc* c, u64 prev_ce, u64 new_ce, u64 sent_time, u64 now);

#endif

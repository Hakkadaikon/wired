#ifndef STATS_STATS_H
#define STATS_STATS_H

#include "common/platform/sys/syscall.h"
#include "transport/recovery/congestion/cc/cc.h"
#include "transport/recovery/detect/recovery/rtt.h"

/** Read-only external view of RTT estimation (RFC 9002 5). No latest_rtt:
 * rtt does not retain the last raw sample, only the smoothed state. */
typedef struct {
  u64 smoothed_rtt;
  u64 min_rtt;
  u64 rttvar;
} stats_rtt;

/** Read-only external view of congestion control state (RFC 9002 7). */
typedef struct {
  u64 cwnd;
  u64 ssthresh;
  int in_recovery;
} stats_cc;

void stats_rtt_get(const rtt* r, stats_rtt* out);
void stats_cc_get(const cc* c, stats_cc* out);

#endif

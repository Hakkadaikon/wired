#ifndef STATS_STATS_H
#define STATS_STATS_H

#include "common/platform/sys/syscall.h"
#include "transport/recovery/congestion/cc/cc.h"
#include "transport/recovery/detect/recovery/rtt.h"
#include "transport/recovery/detect/recovery/sent.h"

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

/** Read-only external view of sent-packet tracking (RFC 9002 A). lost is the
 * count of tracked slots currently in PKT_LOST state. */
typedef struct {
  u64 bytes_in_flight;
  usz lost;
} stats_sent;

void stats_rtt_get(const rtt* r, stats_rtt* out);
void stats_cc_get(const cc* c, stats_cc* out);
void stats_sent_get(const sent* s, stats_sent* out);

#endif

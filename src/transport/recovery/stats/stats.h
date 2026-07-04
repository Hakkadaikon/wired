#ifndef QUIC_STATS_STATS_H
#define QUIC_STATS_STATS_H

#include "common/platform/sys/syscall.h"
#include "transport/recovery/congestion/cc/cc.h"
#include "transport/recovery/detect/recovery/rtt.h"
#include "transport/recovery/detect/recovery/sent.h"

/* Read-only external view of RTT estimation (RFC 9002 5). No latest_rtt:
 * quic_rtt does not retain the last raw sample, only the smoothed state. */
typedef struct {
  u64 smoothed_rtt;
  u64 min_rtt;
  u64 rttvar;
} quic_stats_rtt;

/* Read-only external view of congestion control state (RFC 9002 7). */
typedef struct {
  u64 cwnd;
  u64 ssthresh;
  int in_recovery;
} quic_stats_cc;

/* Read-only external view of sent-packet tracking (RFC 9002 A). lost is the
 * count of tracked slots currently in QUIC_PKT_LOST state. */
typedef struct {
  u64 bytes_in_flight;
  usz lost;
} quic_stats_sent;

void quic_stats_rtt_get(const quic_rtt* r, quic_stats_rtt* out);
void quic_stats_cc_get(const quic_cc* c, quic_stats_cc* out);
void quic_stats_sent_get(const quic_sent* s, quic_stats_sent* out);

#endif

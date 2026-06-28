#ifndef QUIC_LOSSTIME_LOSSTIME_H
#define QUIC_LOSSTIME_LOSSTIME_H

#include "sys/syscall.h"

/* RFC 9002 6.1.2: time-threshold loss detection.
 * loss_delay = max(9/8 * max(srtt, latest_rtt), granularity). */
u64 quic_losstime_threshold(u64 srtt, u64 latest_rtt, u64 granularity);

/* 1 when a packet sent at time_sent is past the time threshold at now,
 * i.e. now >= time_sent + loss_delay. */
int quic_losstime_is_lost(u64 time_sent, u64 now, u64 loss_delay);

#endif

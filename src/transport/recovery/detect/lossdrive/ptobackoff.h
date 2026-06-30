#ifndef QUIC_LOSSDRIVE_PTOBACKOFF_H
#define QUIC_LOSSDRIVE_PTOBACKOFF_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 6.2.1: PTO = srtt + max(4*rttvar, granularity) + max_ack_delay,
 * scaled by 2^pto_count. Times are in microseconds. */
u64 quic_lossdrive_pto(
    u64 smoothed_rtt,
    u64 rttvar,
    u64 max_ack_delay,
    u32 pto_count,
    u64 granularity);

#endif

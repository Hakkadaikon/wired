#ifndef QUIC_RECOVERY_PTO_H
#define QUIC_RECOVERY_PTO_H

#include "sys/syscall.h"

/* RFC 9002 6.2.1: PTO computation and exponential backoff. Times in us. */

#define QUIC_PTO_GRANULARITY 1000 /* kGranularity = 1ms */
#define QUIC_PTO_BACKOFF_MAX 16   /* cap the shift so pto*2^count cannot overflow */

/* 2^count, clamped at 2^QUIC_PTO_BACKOFF_MAX. */
u64 quic_pto_backoff(u32 count);

/* PTO = srtt + max(4*rttvar, granularity) + max_ack_delay, scaled by 2^count. */
u64 quic_pto_duration(u64 srtt, u64 rttvar, u64 max_ack_delay, u32 backoff_count);

#endif

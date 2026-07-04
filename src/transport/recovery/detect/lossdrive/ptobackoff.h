#ifndef QUIC_LOSSDRIVE_PTOBACKOFF_H
#define QUIC_LOSSDRIVE_PTOBACKOFF_H

#include "common/platform/sys/syscall.h"
#include "transport/recovery/detect/recovery/pto.h"

/* Non-RTT inputs to the PTO computation. */
typedef struct {
  u64 max_ack_delay;
  u32 pto_count;
  u64 granularity;
} quic_lossdrive_ptoctx;

/* RFC 9002 6.2.1: PTO = srtt + max(4*rttvar, granularity) + max_ack_delay,
 * scaled by 2^pto_count. Times are in microseconds. */
u64 quic_lossdrive_pto(quic_pto_rtt rtt, const quic_lossdrive_ptoctx* ctx);

#endif

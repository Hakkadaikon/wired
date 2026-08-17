#ifndef QUIC_CC_PACING_H
#define QUIC_CC_PACING_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 7.7: inter-packet interval to smooth bursts.
 * interval = N * packet_size * srtt / cwnd with N = 5/4. Times in us. */

/* 0 when cwnd is 0 (nothing in flight, send immediately). */
u64 pacing_interval(u64 srtt, u64 cwnd, u64 packet_size);

#endif

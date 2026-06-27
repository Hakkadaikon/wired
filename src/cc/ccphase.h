#ifndef QUIC_CC_CCPHASE_H
#define QUIC_CC_CCPHASE_H

#include "sys/syscall.h"

/* RFC 9002 7.3.1/7.3.2: slow-start vs congestion-avoidance window growth.
 * Sizes in bytes. */

/* True while below the slow-start threshold. */
int quic_cc_in_slow_start(u64 cwnd, u64 ssthresh);

/* Slow start (7.3.1): grow by the bytes acknowledged. */
u64 quic_cc_slow_start_inc(u64 acked);

/* Congestion avoidance (7.3.2): grow by max_datagram * acked / cwnd. */
u64 quic_cc_avoid_inc(u64 max_datagram, u64 acked, u64 cwnd);

#endif

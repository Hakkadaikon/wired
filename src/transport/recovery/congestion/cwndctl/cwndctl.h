#ifndef QUIC_CWNDCTL_CWNDCTL_H
#define QUIC_CWNDCTL_CWNDCTL_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 7.7: send control. Admission against the congestion window and the
 * pacing interval that smooths bursts. Delegates to cc/cwndcheck and
 * cc/pacing; this layer fixes the public send-control API. */

/* Returns 1 if sending next_packet_size more bytes keeps bytes_in_flight
 * within cwnd (bytes_in_flight + next <= cwnd), 0 otherwise. */
int cwndctl_can_send(u64 bytes_in_flight, u64 cwnd, usz next_packet_size);

/* RFC 9002 7.7: interval (us) until the next packet may be sent, from pacing
 * rate N * cwnd / smoothed_rtt with N = 5/4. 0 when cwnd is 0. */
u64 cwndctl_pacing_interval(u64 smoothed_rtt, u64 cwnd, usz mtu);

#endif

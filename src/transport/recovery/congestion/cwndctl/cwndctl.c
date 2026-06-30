#include "transport/recovery/congestion/cwndctl/cwndctl.h"

#include "transport/recovery/congestion/cc/cwndcheck.h"
#include "transport/recovery/congestion/cc/pacing.h"

/* RFC 9002 7.5 */
int quic_cwndctl_can_send(u64 bytes_in_flight, u64 cwnd, usz next_packet_size) {
  return quic_cwnd_can_send(bytes_in_flight, cwnd, next_packet_size);
}

/* RFC 9002 7.7 */
u64 quic_cwndctl_pacing_interval(u64 smoothed_rtt, u64 cwnd, usz mtu) {
  return quic_pacing_interval(smoothed_rtt, cwnd, mtu);
}

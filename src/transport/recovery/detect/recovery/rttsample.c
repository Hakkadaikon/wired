#include "transport/recovery/detect/recovery/rttsample.h"

#include "common/bytes/util/num.h"

/* RFC 9002 5.1: min_rtt is the minimum observed latest_rtt. */
u64 quic_rtt_min_update(u64 min_rtt, u64 latest_rtt) {
  return quic_u64_min(min_rtt, latest_rtt);
}

/* RFC 9002 5.3: subtract ack_delay only if it keeps latest_rtt >= min_rtt. */
u64 quic_rtt_adjusted(u64 latest_rtt, u64 min_rtt, u64 ack_delay) {
  return (latest_rtt >= min_rtt + ack_delay) ? latest_rtt - ack_delay
                                             : latest_rtt;
}

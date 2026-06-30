#include "transport/recovery/congestion/cc/pacing.h"

u64 quic_pacing_interval(u64 srtt, u64 cwnd, u64 packet_size) {
  if (cwnd == 0) return 0;
  return 5 * packet_size * srtt / (4 * cwnd);
}

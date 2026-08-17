#include "transport/recovery/congestion/cc/ccphase.h"

int cc_in_slow_start(u64 cwnd, u64 ssthresh) { return cwnd < ssthresh; }

u64 cc_slow_start_inc(u64 acked) { return acked; }

u64 cc_avoid_inc(u64 max_datagram, u64 acked, u64 cwnd) {
  return max_datagram * acked / cwnd;
}

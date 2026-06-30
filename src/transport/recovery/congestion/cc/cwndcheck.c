#include "transport/recovery/congestion/cc/cwndcheck.h"

int quic_cwnd_can_send(u64 in_flight, u64 cwnd, u64 size) {
  return in_flight + size <= cwnd;
}

int quic_cwnd_app_limited(u64 in_flight, u64 cwnd) { return in_flight < cwnd; }

#include "transport/recovery/congestion/cc/persistent.h"

int quic_cc_persistent(u64 loss_period, u64 pto) {
  return loss_period >= 3 * pto;
}

u64 quic_cc_persistent_cwnd(u64 max_datagram) { return 2 * max_datagram; }

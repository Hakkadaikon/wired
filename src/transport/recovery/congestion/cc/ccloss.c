#include "transport/recovery/congestion/cc/ccloss.h"

#include "common/bytes/util/num.h"

u64 quic_cc_on_loss_ssthresh(u64 cwnd) { return cwnd / 2; }

u64 quic_cc_on_loss_cwnd(u64 cwnd, u64 max_datagram) {
  return quic_u64_max(cwnd / 2, 2 * max_datagram);
}

int quic_cc_in_recovery(u64 sent_time, u64 recovery_start) {
  return sent_time <= recovery_start;
}

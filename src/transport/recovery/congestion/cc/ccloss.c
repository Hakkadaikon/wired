#include "transport/recovery/congestion/cc/ccloss.h"

#include "transport/recovery/congestion/cc/cc.h"

int cc_in_recovery(u64 sent_time, u64 recovery_start) {
  return sent_time <= recovery_start;
}

/* RFC 9002 B.8: collapse to kMinimumWindow and clear the recovery period
 * (congestion_recovery_start_time = 0). BBR sizes cwnd from its own model
 * (bbr_set_cwnd), so it is left alone. */
void cc_on_persistent(cc* c) {
  if (c->algo == CC_ALGO_BBR) {
    return;
  }
  c->cwnd           = CC_MIN_WINDOW;
  c->in_recovery    = 0;
  c->recovery_start = 0;
}

#include "transport/recovery/congestion/cc/ecn.h"

int quic_ecn_ce_increased(u64 prev_ce, u64 new_ce) { return new_ce > prev_ce; }

int quic_ecn_counts_valid(quic_ecn_counts prev, quic_ecn_counts next) {
  return next.ce >= prev.ce && next.ect0 >= prev.ect0;
}

void quic_ecn_on_ce_increase(
    quic_cc* c, u64 prev_ce, u64 new_ce, u64 sent_time, u64 now) {
  if (!quic_ecn_ce_increased(prev_ce, new_ce)) return;
  quic_cc_on_loss(c, sent_time, now);
}

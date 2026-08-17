#include "transport/recovery/congestion/cc/ecn.h"

int ecn_ce_increased(u64 prev_ce, u64 new_ce) { return new_ce > prev_ce; }

int ecn_counts_valid(ecn_counts prev, ecn_counts next) {
  return next.ce >= prev.ce && next.ect0 >= prev.ect0;
}

void ecn_on_ce_increase(
    cc* c, u64 prev_ce, u64 new_ce, u64 sent_time, u64 now) {
  if (!ecn_ce_increased(prev_ce, new_ce)) return;
  cc_on_loss(c, sent_time, now);
}

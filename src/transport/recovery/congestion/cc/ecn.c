#include "transport/recovery/congestion/cc/ecn.h"

int quic_ecn_ce_increased(u64 prev_ce, u64 new_ce) { return new_ce > prev_ce; }

int quic_ecn_counts_valid(quic_ecn_counts prev, quic_ecn_counts next) {
  return next.ce >= prev.ce && next.ect0 >= prev.ect0;
}

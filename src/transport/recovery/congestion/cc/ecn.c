#include "transport/recovery/congestion/cc/ecn.h"

int quic_ecn_ce_increased(u64 prev_ce, u64 new_ce) { return new_ce > prev_ce; }

int quic_ecn_counts_valid(
    u64 prev_ce, u64 new_ce, u64 prev_ect0, u64 new_ect0) {
  return new_ce >= prev_ce && new_ect0 >= prev_ect0;
}

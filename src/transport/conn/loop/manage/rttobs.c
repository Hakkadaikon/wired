#include "transport/conn/loop/manage/rttobs.h"

int quic_rttobs_is_edge(int prev_spin, int cur_spin) {
  return (prev_spin != 0) != (cur_spin != 0); /* RFC 9312 3.5: spin flip */
}

int quic_rttobs_sample_ok(int spin_enabled, int saw_edge) {
  return spin_enabled != 0 && saw_edge != 0;
}

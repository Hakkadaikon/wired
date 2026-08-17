#include "transport/recovery/rtx/sentmeta/on_ack.h"

int sentmeta_on_ack(sentmeta* m, u64 acked_pn, sentmeta_acked* out) {
  usz i = sentmeta_find(m, acked_pn);
  if (i == SENTMETA_CAP) return 0;
  out->rtt_sample_time_sent = m->pkts[i].time_sent;
  out->was_ack_eliciting    = m->pkts[i].ack_eliciting;
  sentmeta_reclaim(m, i);
  return 1;
}

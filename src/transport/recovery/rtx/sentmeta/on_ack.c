#include "transport/recovery/rtx/sentmeta/on_ack.h"

int quic_sentmeta_on_ack(
    quic_sentmeta *m, u64 acked_pn, quic_sentmeta_acked *out) {
  usz i = quic_sentmeta_find(m, acked_pn);
  if (i == QUIC_SENTMETA_CAP) return 0;
  out->rtt_sample_time_sent = m->pkts[i].time_sent;
  out->was_ack_eliciting    = m->pkts[i].ack_eliciting;
  quic_sentmeta_reclaim(m, i);
  return 1;
}

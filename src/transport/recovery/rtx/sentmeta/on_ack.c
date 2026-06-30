#include "transport/recovery/rtx/sentmeta/on_ack.h"

int quic_sentmeta_on_ack(
    quic_sentmeta *m,
    u64            acked_pn,
    u64           *rtt_sample_time_sent,
    int           *was_ack_eliciting) {
  usz i = quic_sentmeta_find(m, acked_pn);
  if (i == QUIC_SENTMETA_CAP) return 0;
  *rtt_sample_time_sent = m->pkts[i].time_sent;
  *was_ack_eliciting    = m->pkts[i].ack_eliciting;
  quic_sentmeta_reclaim(m, i);
  return 1;
}

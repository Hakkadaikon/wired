#include "transport/conn/pnspace/pnspaces/sent_spaces.h"

#include "transport/recovery/rtx/sentpkt/ack_process.h"

void quic_pnspaces_sent_init(quic_pnspaces_sent *s) {
  for (int i = 0; i < QUIC_PNS_COUNT; i++) quic_sentpkt_init(&s->t[i]);
}

int quic_pnspaces_on_send(
    quic_pnspaces_sent *s,
    int                 space,
    u64                 pn,
    u64                 time,
    int                 ack_eliciting,
    usz                 size) {
  quic_sentpkt_out pkt = {pn, time, ack_eliciting, size};
  return quic_sentpkt_on_send(&s->t[space], &pkt);
}

void quic_pnspaces_on_ack(
    quic_pnspaces_sent *s,
    int                 space,
    u64                 ack_largest,
    const u64          *ack_ranges,
    usz                 n_ranges,
    u64                *newly_acked_pns,
    usz                *n_acked) {
  quic_ackset ackset = {ack_largest, ack_ranges, n_ranges};
  quic_ack_process(
      &s->t[space], &ackset, (quic_u64out){newly_acked_pns, n_acked});
}

usz quic_pnspaces_sent_count(const quic_pnspaces_sent *s, int space) {
  return quic_sentpkt_count(&s->t[space]);
}

#include "transport/conn/pnspace/pnspaces/sent_spaces.h"

#include "transport/recovery/rtx/sentpkt/ack_process.h"

void quic_pnspaces_sent_init(quic_pnspaces_sent *s) {
  for (int i = 0; i < QUIC_PNS_COUNT; i++) quic_sentpkt_init(&s->t[i]);
}

int quic_pnspaces_on_send(
    quic_pnspaces_sent *s, int space, const quic_sentpkt_out *pkt) {
  return quic_sentpkt_on_send(&s->t[space], pkt);
}

void quic_pnspaces_on_ack(
    quic_pnspaces_sent *s, const quic_pnspaces_ack_in *in, quic_u64out acked) {
  quic_ack_process(&s->t[in->space], &in->ackset, acked);
}

usz quic_pnspaces_sent_count(const quic_pnspaces_sent *s, int space) {
  return quic_sentpkt_count(&s->t[space]);
}

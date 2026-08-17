#include "transport/conn/pnspace/pnspaces/sent_spaces.h"

#include "transport/recovery/rtx/sentpkt/ack_process.h"

void pnspaces_sent_init(pnspaces_sent* s) {
  for (int i = 0; i < PNS_COUNT; i++) sentpkt_init(&s->t[i]);
}

int pnspaces_on_send(pnspaces_sent* s, int space, const sentpkt_out* pkt) {
  return sentpkt_on_send(&s->t[space], pkt);
}

void pnspaces_on_ack(
    pnspaces_sent* s, const pnspaces_ack_in* in, u64out acked) {
  ack_process(&s->t[in->space], &in->ackset, acked);
}

usz pnspaces_sent_count(const pnspaces_sent* s, int space) {
  return sentpkt_count(&s->t[space]);
}

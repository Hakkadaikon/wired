#include "transport/recovery/rtx/sentpkt/sentpkt.h"

void quic_sentpkt_init(quic_sentpkt* t) {
  for (usz i = 0; i < QUIC_SENTPKT_CAP; i++) t->e[i].used = 0;
}

/* First free slot, or QUIC_SENTPKT_CAP when the table is full. */
static usz sentpkt_free_slot(const quic_sentpkt* t) {
  usz i = 0;
  while (i < QUIC_SENTPKT_CAP && t->e[i].used) i++;
  return i;
}

int quic_sentpkt_on_send(quic_sentpkt* t, const quic_sentpkt_out* pkt) {
  usz i = sentpkt_free_slot(t);
  if (i == QUIC_SENTPKT_CAP) return 0;
  t->e[i].pn            = pkt->pn;
  t->e[i].time_sent     = pkt->time;
  t->e[i].size          = pkt->size;
  t->e[i].ack_eliciting = (u8)(pkt->ack_eliciting != 0);
  t->e[i].state         = QUIC_SP_INFLIGHT;
  t->e[i].used          = 1;
  return 1;
}

usz quic_sentpkt_count(const quic_sentpkt* t) {
  usz n = 0;
  for (usz i = 0; i < QUIC_SENTPKT_CAP; i++) n += t->e[i].used;
  return n;
}

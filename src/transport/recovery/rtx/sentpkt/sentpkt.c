#include "transport/recovery/rtx/sentpkt/sentpkt.h"

void sentpkt_init(sentpkt* t) {
  for (usz i = 0; i < SENTPKT_CAP; i++) t->e[i].used = 0;
}

/* First free slot, or SENTPKT_CAP when the table is full. */
static usz sentpkt_free_slot(const sentpkt* t) {
  usz i = 0;
  while (i < SENTPKT_CAP && t->e[i].used) i++;
  return i;
}

int sentpkt_on_send(sentpkt* t, const sentpkt_out* pkt) {
  usz i = sentpkt_free_slot(t);
  if (i == SENTPKT_CAP) return 0;
  t->e[i].pn            = pkt->pn;
  t->e[i].time_sent     = pkt->time;
  t->e[i].size          = pkt->size;
  t->e[i].ack_eliciting = (u8)(pkt->ack_eliciting != 0);
  t->e[i].state         = SP_INFLIGHT;
  t->e[i].used          = 1;
  return 1;
}

usz sentpkt_count(const sentpkt* t) {
  usz n = 0;
  for (usz i = 0; i < SENTPKT_CAP; i++) n += t->e[i].used;
  return n;
}

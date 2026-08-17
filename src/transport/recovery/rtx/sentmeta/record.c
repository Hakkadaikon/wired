#include "transport/recovery/rtx/sentmeta/record.h"

void sentmeta_init(sentmeta* m) {
  for (usz i = 0; i < QUIC_SENTMETA_CAP; i++) m->pkts[i].used = 0;
  m->count           = 0;
  m->total_in_flight = 0;
}

/* First free slot, or QUIC_SENTMETA_CAP when the ring is full. */
static usz sentmeta_free_slot(const sentmeta* m) {
  usz i = 0;
  while (i < QUIC_SENTMETA_CAP && m->pkts[i].used) i++;
  return i;
}

static void sentmeta_store(sentmeta_pkt* p, const sentmeta_out* pkt) {
  p->pn            = pkt->pn;
  p->time_sent     = pkt->time_sent;
  p->ack_eliciting = pkt->ack_eliciting != 0;
  p->in_flight     = pkt->in_flight != 0;
  p->sent_bytes    = pkt->sent_bytes;
  p->used          = 1;
}

int sentmeta_on_sent(sentmeta* m, const sentmeta_out* pkt) {
  usz i = sentmeta_free_slot(m);
  if (i == QUIC_SENTMETA_CAP) return 0;
  sentmeta_store(&m->pkts[i], pkt);
  m->count++;
  if (pkt->in_flight) m->total_in_flight += pkt->sent_bytes;
  return 1;
}

void sentmeta_reclaim(sentmeta* m, usz i) {
  if (m->pkts[i].in_flight) m->total_in_flight -= m->pkts[i].sent_bytes;
  m->pkts[i].used = 0;
  m->count--;
}

static int sentmeta_holds(const sentmeta_pkt* p, u64 pn) {
  return p->used && p->pn == pn;
}

usz sentmeta_find(const sentmeta* m, u64 pn) {
  usz i = 0;
  while (i < QUIC_SENTMETA_CAP && !sentmeta_holds(&m->pkts[i], pn)) i++;
  return i;
}

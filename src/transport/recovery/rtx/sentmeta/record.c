#include "transport/recovery/rtx/sentmeta/record.h"

void quic_sentmeta_init(quic_sentmeta *m) {
  for (usz i = 0; i < QUIC_SENTMETA_CAP; i++) m->pkts[i].used = 0;
  m->count           = 0;
  m->total_in_flight = 0;
}

/* First free slot, or QUIC_SENTMETA_CAP when the ring is full. */
static usz sentmeta_free_slot(const quic_sentmeta *m) {
  usz i = 0;
  while (i < QUIC_SENTMETA_CAP && m->pkts[i].used) i++;
  return i;
}

static void sentmeta_store(
    quic_sentmeta_pkt *p,
    u64                pn,
    u64                time_sent,
    int                ack_eliciting,
    int                in_flight,
    usz                sent_bytes) {
  p->pn            = pn;
  p->time_sent     = time_sent;
  p->ack_eliciting = ack_eliciting != 0;
  p->in_flight     = in_flight != 0;
  p->sent_bytes    = sent_bytes;
  p->used          = 1;
}

int quic_sentmeta_on_sent(
    quic_sentmeta *m,
    u64            pn,
    u64            time_sent,
    int            ack_eliciting,
    int            in_flight,
    usz            sent_bytes) {
  usz i = sentmeta_free_slot(m);
  if (i == QUIC_SENTMETA_CAP) return 0;
  sentmeta_store(
      &m->pkts[i], pn, time_sent, ack_eliciting, in_flight, sent_bytes);
  m->count++;
  if (in_flight) m->total_in_flight += sent_bytes;
  return 1;
}

void quic_sentmeta_reclaim(quic_sentmeta *m, usz i) {
  if (m->pkts[i].in_flight) m->total_in_flight -= m->pkts[i].sent_bytes;
  m->pkts[i].used = 0;
  m->count--;
}

static int sentmeta_holds(const quic_sentmeta_pkt *p, u64 pn) {
  return p->used && p->pn == pn;
}

usz quic_sentmeta_find(const quic_sentmeta *m, u64 pn) {
  usz i = 0;
  while (i < QUIC_SENTMETA_CAP && !sentmeta_holds(&m->pkts[i], pn)) i++;
  return i;
}

#include "transport/recovery/rtx/sentmeta/record.h"

#include "common/bytes/util/bits.h"
#include "common/bytes/util/num.h"

_Static_assert(SENTMETA_CAP % 64 == 0, "live[] is a whole number of words");

void sentmeta_init(sentmeta* m) {
  for (usz i = 0; i < SENTMETA_CAP; i++) {
    m->pkts[i].used = 0;
  }
  for (usz w = 0; w < SENTMETA_CAP / 64; w++) {
    m->live[w] = 0;
  }
  m->count           = 0;
  m->total_in_flight = 0;
}

/* The bits of from's word at or above from, as given (live or free). */
static u64 sentmeta_tail(u64 word, usz from) {
  return word & (~(u64)0 << (from % 64));
}

usz sentmeta_next(const sentmeta* m, usz from) {
  for (; from < SENTMETA_CAP; from = (from | 63) + 1) {
    u64 t = sentmeta_tail(m->live[from / 64], from);
    if (t) {
      return (from & ~(usz)63) + bits_ctz64(t);
    }
  }
  return SENTMETA_CAP;
}

/* First free slot, or SENTMETA_CAP when the ring is full. */
static usz sentmeta_free_slot(const sentmeta* m) {
  for (usz w = 0; w < SENTMETA_CAP / 64; w++) {
    if (~m->live[w]) {
      return w * 64 + bits_ctz64(~m->live[w]);
    }
  }
  return SENTMETA_CAP;
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
  if (i == SENTMETA_CAP) {
    return 0;
  }
  sentmeta_store(&m->pkts[i], pkt);
  m->live[i / 64] |= (u64)1 << (i % 64);
  m->count++;
  if (pkt->in_flight) {
    m->total_in_flight += pkt->sent_bytes;
  }
  return 1;
}

void sentmeta_reclaim(sentmeta* m, usz i) {
  if (m->pkts[i].in_flight) {
    m->total_in_flight -= m->pkts[i].sent_bytes;
  }
  m->pkts[i].used = 0;
  m->live[i / 64] &= ~((u64)1 << (i % 64));
  m->count--;
}

usz sentmeta_find(const sentmeta* m, u64 pn) {
  usz i = sentmeta_next(m, 0);
  while (i < SENTMETA_CAP && m->pkts[i].pn != pn) {
    i = sentmeta_next(m, i + 1);
  }
  return i;
}

void sentmeta_uncount(sentmeta* m, u64 pn, usz n) {
  usz i = sentmeta_find(m, pn);
  if (i >= SENTMETA_CAP || !m->pkts[i].in_flight) {
    return;
  }
  n = (usz)u64_min(n, m->pkts[i].sent_bytes);
  m->pkts[i].sent_bytes -= n;
  m->total_in_flight -= n;
}

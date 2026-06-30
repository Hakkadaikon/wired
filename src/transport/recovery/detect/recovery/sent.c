#include "transport/recovery/detect/recovery/sent.h"

void quic_sent_init(quic_sent *s) {
  for (usz i = 0; i < QUIC_SENT_CAP; i++) s->pkts[i].used = 0;
  s->bytes_in_flight = 0;
  s->largest_acked   = 0;
  s->have_acked      = 0;
}

/* Find a free slot index, or QUIC_SENT_CAP if the table is full. */
static usz free_slot(const quic_sent *s) {
  usz i = 0;
  while (i < QUIC_SENT_CAP && s->pkts[i].used) i++;
  return i;
}

int quic_sent_on_send(quic_sent *s, u64 pn, u64 size, u64 time_sent) {
  usz i = free_slot(s);
  if (i == QUIC_SENT_CAP) return 0;
  s->pkts[i].pn        = pn;
  s->pkts[i].size      = size;
  s->pkts[i].time_sent = time_sent;
  s->pkts[i].state     = QUIC_PKT_INFLIGHT;
  s->pkts[i].used      = 1;
  s->bytes_in_flight += size;
  return 1;
}

/* True if slot i is in use and holds packet number pn. */
static int slot_has_pn(const quic_sent *s, usz i, u64 pn) {
  return s->pkts[i].used && s->pkts[i].pn == pn;
}

/* Locate the in-use slot holding pn, or QUIC_SENT_CAP if absent. */
static usz find_pn(const quic_sent *s, u64 pn) {
  usz i = 0;
  while (i < QUIC_SENT_CAP && !slot_has_pn(s, i, pn)) i++;
  return i;
}

/* Bump largest_acked monotonically. */
static void note_acked(quic_sent *s, u64 pn) {
  if (!s->have_acked || pn > s->largest_acked) s->largest_acked = pn;
  s->have_acked = 1;
}

int quic_sent_on_ack(quic_sent *s, u64 pn) {
  usz i = find_pn(s, pn);
  note_acked(s, pn);
  if (i == QUIC_SENT_CAP || s->pkts[i].state != QUIC_PKT_INFLIGHT) return 0;
  s->bytes_in_flight -= s->pkts[i].size; /* decrement exactly once */
  s->pkts[i].state = QUIC_PKT_ACKED;
  return 1;
}

/* A still-in-flight packet at least kPacketThreshold below largest_acked. */
static int is_lost(const quic_sent *s, usz i) {
  return s->pkts[i].used && s->pkts[i].state == QUIC_PKT_INFLIGHT &&
         s->largest_acked >= s->pkts[i].pn + QUIC_PACKET_THRESHOLD;
}

/* Transition slot i to lost, reclaiming its bytes exactly once. */
static usz lose_one(quic_sent *s, usz i) {
  s->bytes_in_flight -= s->pkts[i].size;
  s->pkts[i].state = QUIC_PKT_LOST;
  return 1;
}

/* Sweep all slots, losing those past the threshold; returns the count. */
static usz sweep_losses(quic_sent *s) {
  usz lost = 0;
  for (usz i = 0; i < QUIC_SENT_CAP; i++)
    if (is_lost(s, i)) lost += lose_one(s, i);
  return lost;
}

usz quic_sent_detect_loss(quic_sent *s) {
  if (!s->have_acked) return 0;
  return sweep_losses(s);
}

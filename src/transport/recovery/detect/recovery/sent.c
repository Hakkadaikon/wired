#include "transport/recovery/detect/recovery/sent.h"

void sent_init(sent* s) {
  for (usz i = 0; i < SENT_CAP; i++) s->pkts[i].used = 0;
  s->bytes_in_flight = 0;
  s->largest_acked   = 0;
  s->have_acked      = 0;
}

/* Find a free slot index, or SENT_CAP if the table is full. */
static usz free_slot(const sent* s) {
  usz i = 0;
  while (i < SENT_CAP && s->pkts[i].used) i++;
  return i;
}

int sent_on_send(sent* s, const sent_out* pkt) {
  usz i = free_slot(s);
  if (i == SENT_CAP) return 0;
  s->pkts[i].pn        = pkt->pn;
  s->pkts[i].size      = pkt->size;
  s->pkts[i].time_sent = pkt->time_sent;
  s->pkts[i].state     = PKT_INFLIGHT;
  s->pkts[i].used      = 1;
  s->bytes_in_flight += pkt->size;
  return 1;
}

/* True if slot i is in use and holds packet number pn. */
static int slot_has_pn(const sent* s, usz i, u64 pn) {
  return s->pkts[i].used && s->pkts[i].pn == pn;
}

/* Locate the in-use slot holding pn, or SENT_CAP if absent. */
static usz find_pn(const sent* s, u64 pn) {
  usz i = 0;
  while (i < SENT_CAP && !slot_has_pn(s, i, pn)) i++;
  return i;
}

/* Bump largest_acked monotonically. */
static void note_acked(sent* s, u64 pn) {
  if (!s->have_acked || pn > s->largest_acked) s->largest_acked = pn;
  s->have_acked = 1;
}

int sent_on_ack(sent* s, u64 pn) {
  usz i = find_pn(s, pn);
  note_acked(s, pn);
  if (i == SENT_CAP || s->pkts[i].state != PKT_INFLIGHT) return 0;
  s->bytes_in_flight -= s->pkts[i].size; /* decrement exactly once */
  s->pkts[i].state = PKT_ACKED;
  return 1;
}

/* A still-in-flight packet at least kPacketThreshold below largest_acked. */
static int is_lost(const sent* s, usz i) {
  return s->pkts[i].used && s->pkts[i].state == PKT_INFLIGHT &&
         s->largest_acked >= s->pkts[i].pn + PACKET_THRESHOLD;
}

/* Transition slot i to lost, reclaiming its bytes exactly once. */
static usz lose_one(sent* s, usz i) {
  s->bytes_in_flight -= s->pkts[i].size;
  s->pkts[i].state = PKT_LOST;
  return 1;
}

/* Sweep all slots, losing those past the threshold; returns the count. */
static usz sweep_losses(sent* s) {
  usz lost = 0;
  for (usz i = 0; i < SENT_CAP; i++)
    if (is_lost(s, i)) lost += lose_one(s, i);
  return lost;
}

usz sent_detect_loss(sent* s) {
  if (!s->have_acked) return 0;
  return sweep_losses(s);
}

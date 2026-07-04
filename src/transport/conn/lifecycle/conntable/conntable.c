#include "transport/conn/lifecycle/conntable/conntable.h"

#include "transport/conn/lifecycle/conn/demux.h"

void quic_conntable_init(quic_conntable* t, usz cap) {
  for (usz i = 0; i < cap; i++) t[i].live = 0;
}

static int conntable_slot_matches(const quic_conntable* slot, quic_span want) {
  return slot->live &&
         quic_demux_match(want, quic_span_of(slot->cid, slot->cid_len));
}

int quic_conntable_find(
    const quic_conntable* t, usz cap, const u8* dcid, u8 dcid_len) {
  quic_span want = quic_span_of(dcid, dcid_len);
  for (usz i = 0; i < cap; i++)
    if (conntable_slot_matches(&t[i], want)) return (int)i;
  return -1;
}

static int conntable_free_slot(const quic_conntable* t, usz cap) {
  for (usz i = 0; i < cap; i++)
    if (!t[i].live) return (int)i;
  return -1;
}

static void conntable_fill_slot(
    quic_conntable* slot, const u8* cid, u8 cid_len) {
  for (u8 i = 0; i < cid_len; i++) slot->cid[i] = cid[i];
  slot->cid_len = cid_len;
  slot->live    = 1;
}

int quic_conntable_insert(
    quic_conntable* t, usz cap, const u8* cid, u8 cid_len) {
  if (cid_len > WIRED_MAX_CID_LEN) return -1;
  int slot = conntable_free_slot(t, cap);
  if (slot < 0) return -1;
  conntable_fill_slot(&t[slot], cid, cid_len);
  return slot;
}

void quic_conntable_remove(quic_conntable* t, usz cap, int i) {
  if (i < 0 || (usz)i >= cap) return;
  t[i].live = 0;
}

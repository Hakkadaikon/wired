#include "transport/conn/lifecycle/conntable/conntable.h"

#include "transport/conn/lifecycle/conn/demux.h"

void quic_conntable_init(quic_conntable* t, usz cap) {
  for (usz i = 0; i < cap; i++) {
    t[i].live        = 0;
    t[i].alt_cid_len = 0;
  }
}

static int conntable_cid_matches(quic_span want, const u8* cid, u8 cid_len) {
  return quic_demux_match(want, quic_span_of(cid, cid_len));
}

/* The alt CID (rekey's stashed prior primary) also routes here, if set. */
static int conntable_alt_matches(const quic_conntable* slot, quic_span want) {
  if (!slot->alt_cid_len) return 0;
  return conntable_cid_matches(want, slot->alt_cid, slot->alt_cid_len);
}

static int conntable_slot_matches(const quic_conntable* slot, quic_span want) {
  if (!slot->live) return 0;
  if (conntable_cid_matches(want, slot->cid, slot->cid_len)) return 1;
  return conntable_alt_matches(slot, want);
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
  slot->cid_len     = cid_len;
  slot->alt_cid_len = 0;
  slot->live        = 1;
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

/* 1 if i names a slot inside a cap-sized table. */
static int conntable_slot_ok(usz cap, int i) { return i >= 0 && (usz)i < cap; }

/* Move slot i's current primary CID into its alt CID slot, freeing the
 * primary for the caller to overwrite. */
static void conntable_stash_alt(quic_conntable* slot) {
  for (u8 j = 0; j < slot->cid_len; j++) slot->alt_cid[j] = slot->cid[j];
  slot->alt_cid_len = slot->cid_len;
}

static void conntable_set_primary(
    quic_conntable* slot, const u8* cid, u8 cid_len) {
  for (u8 j = 0; j < cid_len; j++) slot->cid[j] = cid[j];
  slot->cid_len = cid_len;
}

/* 1 if a rekey of i with cid_len is well-formed (index and CID size). */
static int conntable_rekey_ok(usz cap, int i, u8 cid_len) {
  if (!conntable_slot_ok(cap, i)) return 0;
  return cid_len <= WIRED_MAX_CID_LEN;
}

int quic_conntable_rekey(
    quic_conntable* t, usz cap, int i, const u8* cid, u8 cid_len) {
  if (!conntable_rekey_ok(cap, i, cid_len)) return 0;
  conntable_stash_alt(&t[i]);
  conntable_set_primary(&t[i], cid, cid_len);
  return 1;
}

#include "transport/conn/lifecycle/conntable/conntable_impl.h"

void conntable_init(conntable* t, usz cap) {
  for (usz i = 0; i < cap; i++) {
    t[i].live         = 0;
    t[i].alt_cid_len  = 0;
    t[i].alt2_cid_len = 0;
    t[i].hseed        = 0;
  }
  conntable_reindex(t, cap);
}

static int conntable_free_slot(const conntable* t, usz cap) {
  for (usz i = 0; i < cap; i++) {
    if (!t[i].live) {
      return (int)i;
    }
  }
  return -1;
}

static void conntable_fill_slot(conntable* slot, const u8* cid, u8 cid_len) {
  for (u8 i = 0; i < cid_len; i++) {
    slot->cid[i] = cid[i];
  }
  slot->cid_len      = cid_len;
  slot->alt_cid_len  = 0;
  slot->alt2_cid_len = 0;
  slot->live         = 1;
}

int conntable_insert(conntable* t, usz cap, const u8* cid, u8 cid_len) {
  if (cid_len > WIRED_MAX_CID_LEN) {
    return -1;
  }
  int slot = conntable_free_slot(t, cap);
  if (slot < 0) {
    return -1;
  }
  conntable_fill_slot(&t[slot], cid, cid_len);
  conntable_reindex(t, cap);
  return slot;
}

void conntable_remove(conntable* t, usz cap, int i) {
  if (i < 0 || (usz)i >= cap) {
    return;
  }
  /* No reindex: a dead slot's stale buckets never match (slot_matches checks
   * live) and the next insert rebuilds the index. */
  t[i].live = 0;
}

/* 1 if i names a slot inside a cap-sized table. */
static int conntable_slot_ok(usz cap, int i) { return i >= 0 && (usz)i < cap; }

/* Move slot i's current primary CID into its alt CID slot, freeing the
 * primary for the caller to overwrite. */
static void conntable_stash_alt(conntable* slot) {
  for (u8 j = 0; j < slot->cid_len; j++) {
    slot->alt_cid[j] = slot->cid[j];
  }
  slot->alt_cid_len = slot->cid_len;
}

static void conntable_set_primary(conntable* slot, const u8* cid, u8 cid_len) {
  for (u8 j = 0; j < cid_len; j++) {
    slot->cid[j] = cid[j];
  }
  slot->cid_len = cid_len;
}

/* 1 if a rekey of i with cid_len is well-formed (index and CID size). */
static int conntable_rekey_ok(usz cap, int i, u8 cid_len) {
  if (!conntable_slot_ok(cap, i)) {
    return 0;
  }
  return cid_len <= WIRED_MAX_CID_LEN;
}

int conntable_rekey(conntable* t, usz cap, int i, const u8* cid, u8 cid_len) {
  if (!conntable_rekey_ok(cap, i, cid_len)) {
    return 0;
  }
  conntable_stash_alt(&t[i]);
  conntable_set_primary(&t[i], cid, cid_len);
  conntable_reindex(t, cap);
  return 1;
}

int conntable_set_alt2(
    conntable* t, usz cap, int i, const u8* cid, u8 cid_len) {
  if (!conntable_rekey_ok(cap, i, cid_len)) {
    return 0;
  }
  for (u8 j = 0; j < cid_len; j++) {
    t[i].alt2_cid[j] = cid[j];
  }
  t[i].alt2_cid_len = cid_len;
  conntable_reindex(t, cap);
  return 1;
}

int conntable_set_cid(conntable* t, usz cap, int i, const u8* cid, u8 cid_len) {
  if (!conntable_rekey_ok(cap, i, cid_len)) {
    return 0;
  }
  conntable_set_primary(&t[i], cid, cid_len);
  conntable_reindex(t, cap);
  return 1;
}

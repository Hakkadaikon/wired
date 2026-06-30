#include "app/qpack/qpack/dynfind.h"

static int df_bytes_eq(const u8 *a, usz alen, const u8 *b, usz blen) {
  if (alen != blen) return 0;
  u8 diff = 0;
  for (usz i = 0; i < alen; i++) diff |= (u8)(a[i] ^ b[i]);
  return diff == 0;
}

static int df_name_eq(
    const quic_qpack_dyn_entry *e, const u8 *name, usz name_len) {
  return df_bytes_eq(e->name, e->name_len, name, name_len);
}

static int value_eq(
    const quic_qpack_dyn_entry *e, const u8 *value, usz value_len) {
  return df_bytes_eq(e->value, e->value_len, value, value_len);
}

/* Classify one entry: 2 = name+value, 1 = name only, 0 = no match. */
static int classify(
    const quic_qpack_dyn_entry *e,
    const u8                   *name,
    usz                         name_len,
    const u8                   *value,
    usz                         value_len) {
  if (!df_name_eq(e, name, name_len)) return 0;
  return value_eq(e, value, value_len) ? 2 : 1;
}

static const quic_qpack_dyn_entry *entry_at(const quic_qpack_dyn *t, usz off) {
  return &t->ring[(t->head + off) % QUIC_QPACK_DYN_MAX_ENTRIES];
}

static void record(
    const quic_qpack_dyn *t,
    usz                   off,
    int                   full,
    u64                  *abs_index,
    int                  *value_matched) {
  *abs_index     = t->dropped + off;
  *value_matched = full ? 1 : 0;
}

static int want_name_only(int m, int found) { return m == 1 && !found; }

/* Update best-so-far with entry off; returns 1 to stop (full match found). */
static int scan_one(
    const quic_qpack_dyn *t,
    usz                   off,
    int                  *found,
    const u8             *name,
    usz                   name_len,
    const u8             *value,
    usz                   value_len,
    u64                  *abs_index,
    int                  *value_matched) {
  int m = classify(entry_at(t, off), name, name_len, value, value_len);
  if (m == 2) {
    record(t, off, 1, abs_index, value_matched);
    return 1;
  }
  if (want_name_only(m, *found)) {
    record(t, off, 0, abs_index, value_matched);
    *found = 1;
  }
  return 0;
}

/* RFC 9204 2.1: prefer a full name+value match; fall back to name-only. */
int quic_qpack_dyn_find(
    const quic_qpack_dyn *t,
    const u8             *name,
    usz                   name_len,
    const u8             *value,
    usz                   value_len,
    u64                  *abs_index,
    int                  *value_matched) {
  int found = 0;
  for (usz off = 0; off < t->count; off++)
    if (scan_one(
            t, off, &found, name, name_len, value, value_len, abs_index,
            value_matched))
      return 1;
  return found;
}

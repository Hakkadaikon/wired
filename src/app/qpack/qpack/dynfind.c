#include "app/qpack/qpack/dynfind.h"

static int df_bytes_eq(quic_span a, quic_span b) {
  if (a.n != b.n) return 0;
  u8 diff = 0;
  for (usz i = 0; i < a.n; i++) diff |= (u8)(a.p[i] ^ b.p[i]);
  return diff == 0;
}

static int df_name_eq(const quic_qpack_dyn_entry* e, quic_span name) {
  return df_bytes_eq(quic_span_of(e->name, e->name_len), name);
}

static int value_eq(const quic_qpack_dyn_entry* e, quic_span value) {
  return df_bytes_eq(quic_span_of(e->value, e->value_len), value);
}

/* Classify one entry: 2 = name+value, 1 = name only, 0 = no match. */
static int classify(const quic_qpack_dyn_entry* e, const quic_qpack_field* f) {
  if (!df_name_eq(e, f->name)) return 0;
  return value_eq(e, f->value) ? 2 : 1;
}

static const quic_qpack_dyn_entry* entry_at(const quic_qpack_dyn* t, usz off) {
  return &t->ring[(t->head + off) % QUIC_QPACK_DYN_MAX_ENTRIES];
}

static void record(u64 abs_index, int full, quic_qpack_match* m) {
  m->abs_index     = abs_index;
  m->value_matched = full ? 1 : 0;
}

static int want_name_only(int m, int found) { return m == 1 && !found; }

/* The scan's fixed inputs and its best-so-far state. */
typedef struct {
  const quic_qpack_dyn*   t;
  const quic_qpack_field* f;
  quic_qpack_match*       m;
  int                     found;
} qdf_scan;

/* Update best-so-far with entry off; returns 1 to stop (full match found). */
static int scan_one(qdf_scan* s, usz off) {
  int c = classify(entry_at(s->t, off), s->f);
  if (c == 2) {
    record(s->t->dropped + off, 1, s->m);
    return 1;
  }
  if (want_name_only(c, s->found)) {
    record(s->t->dropped + off, 0, s->m);
    s->found = 1;
  }
  return 0;
}

/* RFC 9204 2.1: prefer a full name+value match; fall back to name-only. */
int quic_qpack_dyn_find(
    const quic_qpack_dyn* t, const quic_qpack_field* f, quic_qpack_match* m) {
  qdf_scan s = {t, f, m, 0};
  for (usz off = 0; off < t->count; off++)
    if (scan_one(&s, off)) return 1;
  return s.found;
}

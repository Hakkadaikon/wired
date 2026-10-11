#include "app/qpack/qpack/dynget.h"

#include "app/qpack/qpack/relindex.h"

/* RFC 9204 3.2.4: an absolute index is live iff dropped <= i < dropped+count.
 * No table (t == 0, e.g. a trailer section) has no live entry. */
static int dyn_in_range(const qpack_dyn* t, u64 abs_index) {
  return abs_index >= t->dropped && abs_index < t->dropped + t->count;
}

static int is_live(const qpack_dyn* t, u64 abs_index) {
  return t && dyn_in_range(t, abs_index);
}

int qpack_dyn_get(const qpack_dyn* t, u64 abs_index, qpack_field* out) {
  if (!is_live(t, abs_index)) return 0;
  usz                    off  = (usz)(abs_index - t->dropped);
  usz                    slot = (t->head + off) % QPACK_DYN_MAX_ENTRIES;
  const qpack_dyn_entry* e    = &t->ring[slot];
  out->name                   = wired_span_of(e->name, e->name_len);
  out->value                  = wired_span_of(e->value, e->value_len);
  return 1;
}

int qpack_dyn_get_enc_rel(const qpack_dyn* t, u64 rel, qpack_field* out) {
  u64 base = t->dropped + t->count;
  return qpack_dyn_get(t, qpack_rel_to_abs(base, rel), out);
}

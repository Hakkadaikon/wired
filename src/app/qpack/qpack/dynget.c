#include "app/qpack/qpack/dynget.h"

#include "app/qpack/qpack/relindex.h"

/* RFC 9204 3.2.4: an absolute index is live iff dropped <= i < dropped+count.
 */
static int is_live(const quic_qpack_dyn* t, u64 abs_index) {
  return abs_index >= t->dropped && abs_index < t->dropped + t->count;
}

int quic_qpack_dyn_get(
    const quic_qpack_dyn* t, u64 abs_index, quic_qpack_field* out) {
  if (!is_live(t, abs_index)) return 0;
  usz off                       = (usz)(abs_index - t->dropped);
  usz slot                      = (t->head + off) % QUIC_QPACK_DYN_MAX_ENTRIES;
  const quic_qpack_dyn_entry* e = &t->ring[slot];
  out->name                     = quic_span_of(e->name, e->name_len);
  out->value                    = quic_span_of(e->value, e->value_len);
  return 1;
}

int quic_qpack_dyn_get_enc_rel(
    const quic_qpack_dyn* t, u64 rel, quic_qpack_field* out) {
  u64 base = t->dropped + t->count;
  return quic_qpack_dyn_get(t, quic_qpack_rel_to_abs(base, rel), out);
}

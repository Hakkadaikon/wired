#include "app/qpack/qpack/dynget.h"

/* RFC 9204 3.2.4: an absolute index is live iff dropped <= i < dropped+count.
 */
static int is_live(const quic_qpack_dyn *t, u64 abs_index) {
  return abs_index >= t->dropped && abs_index < t->dropped + t->count;
}

int quic_qpack_dyn_get(
    const quic_qpack_dyn *t,
    u64                   abs_index,
    const u8            **name,
    usz                  *name_len,
    const u8            **value,
    usz                  *value_len) {
  if (!is_live(t, abs_index)) return 0;
  usz off                       = (usz)(abs_index - t->dropped);
  usz slot                      = (t->head + off) % QUIC_QPACK_DYN_MAX_ENTRIES;
  const quic_qpack_dyn_entry *e = &t->ring[slot];
  *name                         = e->name;
  *name_len                     = e->name_len;
  *value                        = e->value;
  *value_len                    = e->value_len;
  return 1;
}

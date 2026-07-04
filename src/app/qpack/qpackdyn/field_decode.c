#include "app/qpack/qpackdyn/field_decode.h"

#include "app/qpack/qpack/dynget.h"
#include "app/qpack/qpack/fieldline.h"
#include "app/qpack/qpack/relindex.h"
#include "app/qpack/qpack/static_table.h"
#include "app/qpack/qpackdyn/cstr.h"

/* RFC 9204 4.5.2. Resolve a static-table index into borrowed name/value views
 * with their measured lengths. Returns 1 ok, 0 if the index is out of range. */
static int resolve_static(u64 index, quic_qpack_field* out) {
  const char *n, *v;
  if (!quic_qpack_static_get((usz)index, &n, &v)) return 0;
  out->name  = quic_span_of((const u8*)n, quic_qdyn_cstr_len(n));
  out->value = quic_span_of((const u8*)v, quic_qdyn_cstr_len(v));
  return 1;
}

/* RFC 9204 4.5.2 / 3.2.5. Resolve a dynamic relative index against the Base
 * into a borrowed live entry. Returns 1 ok, 0 if no live entry resolves. */
static int resolve_dynamic(
    const quic_qdyn_src* s, u64 rel, quic_qpack_field* out) {
  u64 abs = quic_qpack_rel_to_abs(s->base, rel);
  return quic_qpack_dyn_get(s->table, abs, out);
}

int quic_qdyn_decode_field(
    const quic_qdyn_src* src, quic_qpack_field* out, usz* consumed) {
  u64 index;
  int is_static;
  usz used = quic_qpack_indexed_decode(src->fs, &index, &is_static);
  if (used == 0) return 0;
  *consumed = used;
  if (is_static) return resolve_static(index, out);
  return resolve_dynamic(src, index, out);
}

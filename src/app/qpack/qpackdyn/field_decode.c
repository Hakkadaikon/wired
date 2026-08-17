#include "app/qpack/qpackdyn/field_decode.h"

#include "app/qpack/qpack/dynget.h"
#include "app/qpack/qpack/fieldline.h"
#include "app/qpack/qpack/relindex.h"
#include "app/qpack/qpack/static_table.h"
#include "app/qpack/qpackdyn/cstr.h"

/* RFC 9204 4.5.2. Resolve a static-table index into borrowed name/value views
 * with their measured lengths. Returns 1 ok, 0 if the index is out of range. */
static int resolve_static(u64 index, qpack_field* out) {
  const char *n, *v;
  if (!qpack_static_get((usz)index, &n, &v)) return 0;
  out->name  = wired_span_of((const u8*)n, qdyn_cstr_len(n));
  out->value = wired_span_of((const u8*)v, qdyn_cstr_len(v));
  return 1;
}

/* RFC 9204 4.5.2 / 3.2.5. Resolve a dynamic relative index against the Base
 * into a borrowed live entry. Returns 1 ok, 0 if no live entry resolves. */
static int resolve_dynamic(const qdyn_src* s, u64 rel, qpack_field* out) {
  u64 abs = qpack_rel_to_abs(s->base, rel);
  return qpack_dyn_get(s->table, abs, out);
}

/* RFC 9204 4.5.3 / 3.2.6. Resolve a dynamic post-Base index against the Base
 * into a borrowed live entry. Returns 1 ok, 0 if no live entry resolves. */
static int resolve_postbase(const qdyn_src* s, u64 postbase, qpack_field* out) {
  u64 abs = qpack_postbase_to_abs(s->base, postbase);
  return qpack_dyn_get(s->table, abs, out);
}

/* Try an Indexed Field Line (RFC 9204 4.5.2). Returns 1 with *out and
 * *consumed filled, 0 if the pattern does not match or the reference does
 * not resolve. */
static int try_indexed(const qdyn_src* src, qpack_field* out, usz* consumed) {
  u64 index;
  int is_static;
  usz used = qpack_indexed_decode(src->fs, &index, &is_static);
  if (used == 0) return 0;
  *consumed = used;
  return is_static ? resolve_static(index, out)
                   : resolve_dynamic(src, index, out);
}

/* Try an Indexed Field Line with Post-Base Index (RFC 9204 4.5.3). Returns 1
 * with *out and *consumed filled, 0 if the pattern does not match or the
 * reference does not resolve. */
static int try_postbase(const qdyn_src* src, qpack_field* out, usz* consumed) {
  u64 postbase;
  usz used = qpack_indexed_postbase_decode(src->fs, &postbase);
  if (used == 0) return 0;
  *consumed = used;
  return resolve_postbase(src, postbase, out);
}

int qdyn_decode_field(const qdyn_src* src, qpack_field* out, usz* consumed) {
  if (try_indexed(src, out, consumed)) return 1;
  return try_postbase(src, out, consumed);
}

int qdyn_resolve_postbase_name(
    const qdyn_src* src, u64 postbase, wired_span* name) {
  qpack_field f;
  if (!resolve_postbase(src, postbase, &f)) return 0;
  *name = f.name;
  return 1;
}

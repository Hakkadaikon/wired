#include "app/qpack/qpackdyn/field_encode.h"

#include "app/qpack/qpack/fieldline.h"

usz quic_qdyn_indexed_dynamic(u64 rel_index, quic_obuf* out) {
  /* RFC 9204 4.5.2: is_static=0 selects the dynamic table (T=0). */
  usz w =
      quic_qpack_indexed_encode(quic_mspan_of(out->p, out->cap), rel_index, 0);
  if (w == 0) return 0;
  out->len = w;
  return w;
}

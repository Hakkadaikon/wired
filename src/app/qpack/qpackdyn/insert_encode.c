#include "app/qpack/qpackdyn/insert_encode.h"

#include "app/qpack/qpack/integer.h"
#include "app/qpack/qpack/string.h"
#include "common/bytes/util/bytes.h"

/* RFC 9204 4.3.3. First byte top bits 01, then H (0x20); the 5-bit prefix
 * carries the name length. */
#define QPACK_INSERT_LITNAME 0x40

/* RFC 9204 4.3.3. Encode the name as a string with a 5-bit prefixed length.
 * Returns bytes written, or 0 if the prefix or the name does not fit. */
static usz encode_name(wired_mspan out, wired_span name) {
  qpack_pfx pfx = {5, QPACK_INSERT_LITNAME};
  return qpack_string_encode_pfx(out, name, pfx);
}

usz qdyn_insert_literal(const qpack_field* f, wired_obuf* out) {
  usz off = encode_name(wired_mspan_of(out->p, out->cap), f->name);
  usz w   = off ? qpack_string_encode(
                      wired_mspan_of(out->p + off, out->cap - off), f->value)
                : 0;
  if (w == 0) {
    return 0;
  }
  out->len = off + w;
  return out->len;
}

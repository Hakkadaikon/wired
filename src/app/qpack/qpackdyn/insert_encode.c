#include "app/qpack/qpackdyn/insert_encode.h"

#include "app/qpack/qpack/integer.h"
#include "app/qpack/qpack/string.h"
#include "common/bytes/util/bytes.h"

/* RFC 9204 4.3.3. First byte top bits 010 (H=0); the 5-bit prefix carries the
 * name length. */
#define QPACK_INSERT_LITNAME 0x40

/* RFC 9204 4.3.3. Encode the 5-bit prefixed name length then the name octets.
 * Returns bytes written, or 0 if the prefix or the name does not fit. */
static usz encode_name(quic_mspan out, quic_span name) {
  quic_qpack_pfx pfx = {5, QPACK_INSERT_LITNAME};
  usz            off = quic_qpack_int_encode(out, pfx, name.n);
  if (off == 0) return 0;
  if (!quic_put_bytes(
          quic_mspan_of(out.p, out.n), &off, quic_span_of(name.p, name.n)))
    return 0;
  return off;
}

usz quic_qdyn_insert_literal(const quic_qpack_field *f, quic_obuf *out) {
  usz off = encode_name(quic_mspan_of(out->p, out->cap), f->name);
  usz w   = off ? quic_qpack_string_encode(
                    quic_mspan_of(out->p + off, out->cap - off), f->value)
                : 0;
  if (w == 0) return 0;
  out->len = off + w;
  return out->len;
}

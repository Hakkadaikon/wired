#include "tls/handshake/core/tls/tpext.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"

/* RFC 9001 8.2: extension_type(2) + extension_data length(2) + data. */
usz quic_tpext_encode(quic_obuf *out, quic_span tp) {
  usz off = 4;
  if (tp.n > 0xFFFF || off + tp.n > out->cap) return 0;
  quic_put_be16(out->p, QUIC_TPEXT_TYPE);
  quic_put_be16(out->p + 2, (u16)tp.n);
  quic_put_bytes(
      quic_mspan_of(out->p, out->cap), &off,
      quic_span_of(tp.p, tp.n)); /* room checked above */
  out->len = off;
  return off;
}

/* Validate the 4-byte header and read the data length into *len. */
static int tpext_head(quic_span buf, usz *len) {
  if (buf.n < 4 || ((u16)buf.p[0] << 8 | buf.p[1]) != QUIC_TPEXT_TYPE) return 0;
  *len = (usz)buf.p[2] << 8 | buf.p[3];
  return 4 + *len <= buf.n;
}

usz quic_tpext_decode(quic_span buf, quic_span *tp) {
  usz len;
  if (!tpext_head(buf, &len)) return 0;
  *tp = quic_span_of(buf.p + 4, len);
  return 4 + len;
}

#include "tls/handshake/core/tls/alpn.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"

/* A single protocol name fits one byte and leaves room for the 3-byte head. */
static int alpn_fits(usz proto_len, usz cap) {
  if (proto_len == 0 || proto_len > 0xFF) return 0;
  return 3 + proto_len <= cap;
}

/* RFC 7301 3.1: list length(2) + name length(1) + proto. */
usz quic_tls_alpn_encode(quic_obuf* out, quic_span proto) {
  usz off = 3;
  if (!alpn_fits(proto.n, out->cap)) return 0;
  quic_put_be16(out->p, (u16)(1 + proto.n));
  out->p[2] = (u8)proto.n;
  quic_put_bytes(
      quic_mspan_of(out->p, out->cap), &off,
      quic_span_of(proto.p, proto.n)); /* room checked above */
  out->len = off;
  return off;
}

/* Validate the list framing and read the first name length into *name_len. */
static int alpn_head(quic_span buf, usz list_len, usz* name_len) {
  if (list_len < 1 || 2 + list_len > buf.n) return 0;
  *name_len = buf.p[2];
  return 1 + *name_len <= list_len;
}

usz quic_tls_alpn_decode_first(quic_span buf, quic_span* proto) {
  usz list_len, name_len;
  if (buf.n < 3) return 0;
  list_len = (usz)buf.p[0] << 8 | buf.p[1];
  if (!alpn_head(buf, list_len, &name_len)) return 0;
  *proto = quic_span_of(buf.p + 3, name_len);
  return 2 + list_len;
}

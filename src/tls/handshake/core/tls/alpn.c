#include "tls/handshake/core/tls/alpn.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"

/* A single protocol name fits one byte and leaves room for the 3-byte head. */
static int alpn_fits(usz proto_len, usz cap) {
  if (proto_len == 0 || proto_len > 0xFF) {
    return 0;
  }
  return 3 + proto_len <= cap;
}

/* RFC 7301 3.1: list length(2) + name length(1) + proto. */
usz tls_alpn_encode(wired_obuf* out, wired_span proto) {
  usz off = 3;
  if (!alpn_fits(proto.n, out->cap)) {
    return 0;
  }
  be_put_be16(out->p, (u16)(1 + proto.n));
  out->p[2] = (u8)proto.n;
  bytes_put(
      wired_mspan_of(out->p, out->cap), &off,
      wired_span_of(proto.p, proto.n)); /* room checked above */
  out->len = off;
  return off;
}

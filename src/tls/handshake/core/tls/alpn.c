#include "tls/handshake/core/tls/alpn.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"

/* A single protocol name fits one byte and leaves room for the 3-byte head. */
static int alpn_fits(usz proto_len, usz cap) {
  if (proto_len == 0 || proto_len > 0xFF) return 0;
  return 3 + proto_len <= cap;
}

/* RFC 7301 3.1: list length(2) + name length(1) + proto. */
usz quic_tls_alpn_encode(u8 *buf, usz cap, const u8 *proto, usz proto_len) {
  usz off = 3;
  if (!alpn_fits(proto_len, cap)) return 0;
  quic_put_be16(buf, (u16)(1 + proto_len));
  buf[2] = (u8)proto_len;
  quic_put_bytes(buf, cap, &off, proto, proto_len); /* room checked above */
  return off;
}

/* Validate the list framing and read the first name length into *name_len. */
static int alpn_head(const u8 *buf, usz n, usz list_len, usz *name_len) {
  if (list_len < 1 || 2 + list_len > n) return 0;
  *name_len = buf[2];
  return 1 + *name_len <= list_len;
}

usz quic_tls_alpn_decode_first(
    const u8 *buf, usz n, const u8 **proto, usz *proto_len) {
  usz list_len, name_len;
  if (n < 3) return 0;
  list_len = (usz)buf[0] << 8 | buf[1];
  if (!alpn_head(buf, n, list_len, &name_len)) return 0;
  *proto     = buf + 3;
  *proto_len = name_len;
  return 2 + list_len;
}

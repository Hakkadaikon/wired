#include "tls/handshake/core/tls/alpn_match.h"

/* RFC 7301 3.2: byte-for-byte comparison of protocol names. */
int quic_tls_alpn_equal(quic_span a, quic_span b) {
  u8 diff = 0;
  if (a.n != b.n) return 0;
  for (usz i = 0; i < a.n; i++) diff |= a.p[i] ^ b.p[i];
  return diff == 0;
}

int quic_tls_alpn_is_h3(const u8 *proto, usz len) {
  static const u8 h3[2] = {0x68, 0x33};
  return quic_tls_alpn_equal(quic_span_of(proto, len), quic_span_of(h3, 2));
}

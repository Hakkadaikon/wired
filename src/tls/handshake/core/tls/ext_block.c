#include "tls/handshake/core/tls/ext_block.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"

/* RFC 8446 4.1.2: reserve the 2-byte extensions length. */
int quic_tls_ext_block_begin(const u8 *buf, usz cap, usz *off) {
  if (cap < 2) return 0;
  (void)buf;
  *off = 2;
  return 1;
}

int quic_tls_ext_append(quic_obuf *out, quic_span ext) {
  return quic_put_bytes(out->p, out->cap, &out->len, ext.p, ext.n);
}

/* Back-fill the reserved length to span everything past block_start + 2. */
usz quic_tls_ext_block_finish(u8 *buf, usz off, usz block_start) {
  usz body = off - block_start - 2;
  if (body > 0xFFFF) return 0;
  quic_put_be16(buf + block_start, (u16)body);
  return off;
}

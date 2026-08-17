#include "tls/handshake/core/tls/ext_block.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"

/* RFC 8446 4.1.2: reserve the 2-byte extensions length. */
int tls_ext_block_begin(const u8* buf, usz cap, usz* off) {
  if (cap < 2) return 0;
  (void)buf;
  *off = 2;
  return 1;
}

int tls_ext_append(wired_obuf* out, wired_span ext) {
  return bytes_put(
      wired_mspan_of(out->p, out->cap), &out->len, wired_span_of(ext.p, ext.n));
}

/* Back-fill the reserved length to span everything past block_start + 2. */
usz tls_ext_block_finish(u8* buf, usz off, usz block_start) {
  usz body = off - block_start - 2;
  if (body > 0xFFFF) return 0;
  be_put_be16(buf + block_start, (u16)body);
  return off;
}

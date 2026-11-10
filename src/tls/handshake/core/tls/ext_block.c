#include "tls/handshake/core/tls/ext_block.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"

int tls_ext_append(wired_obuf* out, wired_span ext) {
  return bytes_put(
      wired_mspan_of(out->p, out->cap), &out->len, wired_span_of(ext.p, ext.n));
}

/* Back-fill the reserved length to span everything past block_start + 2. */
usz tls_ext_block_finish(u8* buf, usz off, usz block_start) {
  usz body = off - block_start - 2;
  if (body > 0xFFFF) {
    return 0;
  }
  be_put_be16(buf + block_start, (u16)body);
  return off;
}

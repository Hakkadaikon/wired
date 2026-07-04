#include "transport/stream/flow/flow/stream_read.h"

/* RFC 9000 2.2 */
void quic_stream_read_init(quic_stream_read* s) {
  quic_reasm_init(&s->r);
  s->read_off = 0;
}

/* RFC 9000 2.2 */
int quic_stream_read_push(quic_stream_read* s, u64 offset, quic_span data) {
  return quic_reasm_insert(&s->r, offset, data);
}

/* RFC 9000 2.2: contiguous bytes available past the read position. */
static usz readable(quic_stream_read* s, usz cap) {
  u64 avail = quic_reasm_deliver(&s->r) - s->read_off;
  return avail < cap ? (usz)avail : cap;
}

/* RFC 9000 2.2 */
void quic_stream_read_pull(quic_stream_read* s, quic_obuf* out) {
  usz n = readable(s, out->cap);
  for (usz i = 0; i < n; i++) out->p[i] = s->r.buf[s->read_off + i];
  s->read_off += n;
  out->len = n;
}

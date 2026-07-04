#include "app/http3/request/h3req/reqbuild.h"

#include "app/http3/core/h3/frame.h"

/* Append a DATA frame after out->len when there is a body; out->len is left
 * unchanged for an empty body. Returns 1 ok, 0 if out lacks capacity. */
static int append_body(quic_span body, quic_obuf* out) {
  quic_obuf ob;
  usz       n;
  if (!body.n) return 1;
  ob = quic_obuf_of(out->p + out->len, out->cap - out->len);
  n  = quic_h3_frame_put(&ob, QUIC_H3_FRAME_DATA, body);
  if (!n) return 0;
  out->len += n;
  return 1;
}

/* RFC 9114 4.1 */
int quic_h3req_build(quic_span qpack_headers, quic_span body, quic_obuf* out) {
  quic_obuf head = quic_obuf_of(out->p, out->cap);
  usz off = quic_h3_frame_put(&head, QUIC_H3_FRAME_HEADERS, qpack_headers);
  if (!off) return 0;
  out->len = off;
  return append_body(body, out);
}

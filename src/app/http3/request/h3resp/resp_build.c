#include "app/http3/request/h3resp/resp_build.h"

#include "app/http3/core/h3/frame.h"
#include "app/http3/request/h3resp/field_encode.h"

/* Append a DATA frame after out->len when there is a body; out->len is left
 * unchanged for an empty body. Returns 1 ok, 0 if out lacks capacity. */
static int resp_append_body(quic_span body, quic_obuf* out) {
  quic_obuf ob;
  usz       n;
  if (!body.n) return 1;
  ob = quic_obuf_of(out->p + out->len, out->cap - out->len);
  n  = quic_h3_frame_put(&ob, QUIC_H3_FRAME_DATA, body);
  if (!n) return 0;
  out->len += n;
  return 1;
}

/* Emit the HEADERS frame carrying the :status (plus content-type, when
 * given) field section into out. Returns its byte length, or 0 if encoding
 * or framing lacks capacity. */
static usz put_headers(u16 status, const char* content_type, quic_obuf* out) {
  u8        field[64];
  quic_obuf fob = quic_obuf_of(field, sizeof field);
  if (!quic_h3resp_encode_headers(status, content_type, &fob)) return 0;
  return quic_h3_frame_put(
      out, QUIC_H3_FRAME_HEADERS, quic_span_of(field, fob.len));
}

/* RFC 9114 4.1 */
int quic_h3resp_build(
    u16 status, const char* content_type, quic_span body, quic_obuf* out) {
  quic_obuf head = quic_obuf_of(out->p, out->cap);
  usz       off  = put_headers(status, content_type, &head);
  if (!off) return 0;
  out->len = off;
  return resp_append_body(body, out);
}

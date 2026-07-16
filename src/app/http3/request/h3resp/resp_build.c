#include "app/http3/request/h3resp/resp_build.h"

#include "app/http3/core/h3/frame.h"
#include "app/http3/request/h3resp/field_encode.h"
#include "common/bytes/varint/varint.h"

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

/* Emit the HEADERS frame carrying the :status (plus content-type and extra,
 * when given) field section into out. Returns its byte length, or 0 if
 * encoding or framing lacks capacity. */
static usz put_headers(
    u16                     status,
    const char*             content_type,
    const quic_qpack_field* extra,
    quic_obuf*              out) {
  u8        field[192];
  quic_obuf fob = quic_obuf_of(field, sizeof field);
  if (!quic_h3resp_encode_headers_field(status, content_type, extra, &fob))
    return 0;
  return quic_h3_frame_put(
      out, QUIC_H3_FRAME_HEADERS, quic_span_of(field, fob.len));
}

/* RFC 9114 4.1 */
int quic_h3resp_build(
    u16 status, const char* content_type, quic_span body, quic_obuf* out) {
  quic_obuf head = quic_obuf_of(out->p, out->cap);
  usz       off  = put_headers(status, content_type, 0, &head);
  if (!off) return 0;
  out->len = off;
  return resp_append_body(body, out);
}

/* Append the DATA frame header (type 0x00 + length varint) after out->len;
 * skipped entirely for an empty body (RFC 9114 7.1). */
static int prefix_data_hdr(u64 body_len, quic_obuf* out) {
  usz off = out->len;
  int ok;
  if (!body_len) return 1;
  ok = quic_varint_put(
           quic_mspan_of(out->p, out->cap), &off, QUIC_H3_FRAME_DATA) &
       quic_varint_put(quic_mspan_of(out->p, out->cap), &off, body_len);
  if (!ok) return 0;
  out->len = off;
  return 1;
}

int quic_h3resp_prefix_field(
    u16                     status,
    const char*             content_type,
    u64                     body_len,
    const quic_qpack_field* extra,
    quic_obuf*              out) {
  quic_obuf head = quic_obuf_of(out->p, out->cap);
  usz       off  = put_headers(status, content_type, extra, &head);
  if (!off) return 0;
  out->len = off;
  return prefix_data_hdr(body_len, out);
}

int quic_h3resp_prefix(
    u16 status, const char* content_type, u64 body_len, quic_obuf* out) {
  return quic_h3resp_prefix_field(status, content_type, body_len, 0, out);
}

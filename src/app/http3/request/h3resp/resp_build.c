#include "app/http3/request/h3resp/resp_build.h"

#include "app/http3/core/h3/frame.h"
#include "app/http3/request/h3resp/field_encode.h"
#include "common/bytes/varint/varint.h"

/* Append a DATA frame after out->len when there is a body; out->len is left
 * unchanged for an empty body. Returns 1 ok, 0 if out lacks capacity. */
static int resp_append_body(wired_span body, wired_obuf* out) {
  wired_obuf ob;
  usz        n;
  if (!body.n) return 1;
  ob = obuf_of(out->p + out->len, out->cap - out->len);
  n  = h3_frame_put(&ob, H3_FRAME_DATA, body);
  if (!n) return 0;
  out->len += n;
  return 1;
}

/* Emit the HEADERS frame carrying the :status (plus content-type and extra,
 * when given) field section into out. Returns its byte length, or 0 if
 * encoding or framing lacks capacity. */
static usz put_headers(
    u16                status,
    const char*        content_type,
    const qpack_field* extra,
    wired_obuf*        out) {
  u8         field[192];
  wired_obuf fob = obuf_of(field, sizeof field);
  if (!h3resp_encode_headers_field(status, content_type, extra, &fob)) return 0;
  return h3_frame_put(out, H3_FRAME_HEADERS, wired_span_of(field, fob.len));
}

/* RFC 9114 4.1 */
int h3resp_build(
    u16 status, const char* content_type, wired_span body, wired_obuf* out) {
  wired_obuf head = obuf_of(out->p, out->cap);
  usz        off  = put_headers(status, content_type, 0, &head);
  if (!off) return 0;
  out->len = off;
  return resp_append_body(body, out);
}

/* Append the DATA frame header (type 0x00 + length varint) after out->len;
 * skipped entirely for an empty body (RFC 9114 7.1). */
static int prefix_data_hdr(u64 body_len, wired_obuf* out) {
  usz off = out->len;
  int ok;
  if (!body_len) return 1;
  ok = varint_put(wired_mspan_of(out->p, out->cap), &off, H3_FRAME_DATA) &
       varint_put(wired_mspan_of(out->p, out->cap), &off, body_len);
  if (!ok) return 0;
  out->len = off;
  return 1;
}

int h3resp_prefix_field(
    u16                status,
    const char*        content_type,
    u64                body_len,
    const qpack_field* extra,
    wired_obuf*        out) {
  wired_obuf head = obuf_of(out->p, out->cap);
  usz        off  = put_headers(status, content_type, extra, &head);
  if (!off) return 0;
  out->len = off;
  return prefix_data_hdr(body_len, out);
}

int h3resp_prefix(
    u16 status, const char* content_type, u64 body_len, wired_obuf* out) {
  return h3resp_prefix_field(status, content_type, body_len, 0, out);
}

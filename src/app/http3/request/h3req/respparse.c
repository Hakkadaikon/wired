#include "app/http3/request/h3req/respparse.h"

#include "app/http3/core/h3/frame.h"

/* Read one frame of an expected type. Returns bytes consumed, 0 on a
 * truncated frame or a type mismatch. */
static usz get_typed(
    const u8 *buf, usz n, u64 want, const u8 **payload, usz *plen) {
  u64 type, len;
  usz used = quic_h3_frame_get(buf, n, &type, payload, &len);
  if (!used || type != want) return 0;
  *plen = (usz)len;
  return used;
}

/* Parse the optional trailing DATA frame. An empty remainder leaves *body
 * empty and succeeds; a present-but-malformed remainder fails. */
static int parse_body(const u8 *rem, usz len, const u8 **body, usz *body_len) {
  *body     = 0;
  *body_len = 0;
  if (!len) return 1;
  return get_typed(rem, len, QUIC_H3_FRAME_DATA, body, body_len) != 0;
}

/* RFC 9114 4.1 */
int quic_h3req_resp_parse(
    const u8  *stream,
    usz        len,
    const u8 **headers,
    usz       *h_len,
    const u8 **body,
    usz       *body_len) {
  usz off = get_typed(stream, len, QUIC_H3_FRAME_HEADERS, headers, h_len);
  if (!off) return 0;
  return parse_body(stream + off, len - off, body, body_len);
}

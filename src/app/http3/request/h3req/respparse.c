#include "app/http3/request/h3req/respparse.h"

#include "app/http3/core/h3/frame.h"

/* Read one frame of an expected type. Returns bytes consumed, 0 on a
 * truncated frame or a type mismatch. */
static usz get_typed(wired_span buf, u64 want, wired_span* payload) {
  h3_frame f;
  usz      used = h3_frame_get(buf, &f);
  if (!used || f.type != want) return 0;
  *payload = wired_span_of(f.payload, (usz)f.payload_len);
  return used;
}

/* Parse the optional trailing DATA frame. An empty remainder leaves body
 * empty and succeeds; a present-but-malformed remainder fails. */
static int parse_body(wired_span rem, wired_span* body) {
  *body = wired_span_of(0, 0);
  if (!rem.n) return 1;
  return get_typed(rem, QUIC_H3_FRAME_DATA, body) != 0;
}

/* RFC 9114 4.1 */
int h3req_resp_parse(wired_span stream, h3req_resp* resp) {
  usz off = get_typed(stream, QUIC_H3_FRAME_HEADERS, &resp->headers);
  if (!off) return 0;
  return parse_body(wired_span_of(stream.p + off, stream.n - off), &resp->body);
}

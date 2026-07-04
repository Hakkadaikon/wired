#include "app/http3/request/h3req/respparse.h"

#include "app/http3/core/h3/frame.h"

/* Read one frame of an expected type. Returns bytes consumed, 0 on a
 * truncated frame or a type mismatch. */
static usz get_typed(quic_span buf, u64 want, quic_span* payload) {
  quic_h3_frame f;
  usz           used = quic_h3_frame_get(buf, &f);
  if (!used || f.type != want) return 0;
  *payload = quic_span_of(f.payload, (usz)f.payload_len);
  return used;
}

/* Parse the optional trailing DATA frame. An empty remainder leaves body
 * empty and succeeds; a present-but-malformed remainder fails. */
static int parse_body(quic_span rem, quic_span* body) {
  *body = quic_span_of(0, 0);
  if (!rem.n) return 1;
  return get_typed(rem, QUIC_H3_FRAME_DATA, body) != 0;
}

/* RFC 9114 4.1 */
int quic_h3req_resp_parse(quic_span stream, quic_h3req_resp* resp) {
  usz off = get_typed(stream, QUIC_H3_FRAME_HEADERS, &resp->headers);
  if (!off) return 0;
  return parse_body(quic_span_of(stream.p + off, stream.n - off), &resp->body);
}

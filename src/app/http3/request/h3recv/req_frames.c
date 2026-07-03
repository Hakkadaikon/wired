#include "app/http3/request/h3recv/req_frames.h"

#include "app/http3/core/h3/frame.h"

int quic_h3req_recv_first_headers(quic_span stream, quic_span *field_section) {
  quic_h3_frame f;
  /* RFC 9114 4.1: the first frame on a request stream is HEADERS. */
  if (quic_h3_frame_get(stream, &f) == 0) return 0;
  if (f.type != QUIC_H3_FRAME_HEADERS) return 0;
  *field_section = quic_span_of(f.payload, (usz)f.payload_len);
  return 1;
}

#include "app/http3/core/h3/reqstream.h"

#include "app/http3/core/h3/frame.h"

/* A HEADERS frame is the leading header section from START, otherwise the
 * trailer section (allowed only after the leading HEADERS or some DATA). */
static int on_headers(quic_h3_req_state *state) {
  if (*state == QUIC_H3_REQ_START) {
    *state = QUIC_H3_REQ_HEADERS;
    return 1;
  }
  if (*state == QUIC_H3_REQ_TRAILERS) return 0;
  *state = QUIC_H3_REQ_TRAILERS; /* trailer after HEADERS or DATA */
  return 1;
}

/* DATA is allowed only after the leading HEADERS (and may repeat); never
 * before HEADERS and never after the trailer section. */
static int on_data(quic_h3_req_state *state) {
  if (*state == QUIC_H3_REQ_HEADERS || *state == QUIC_H3_REQ_DATA) {
    *state = QUIC_H3_REQ_DATA;
    return 1;
  }
  return 0;
}

int quic_h3_reqstream_frame(quic_h3_req_state *state, u64 frame_type) {
  if (frame_type == QUIC_H3_FRAME_HEADERS) return on_headers(state);
  if (frame_type == QUIC_H3_FRAME_DATA) return on_data(state);
  return 0; /* RFC 9114 7.1: other frame types are not valid here */
}

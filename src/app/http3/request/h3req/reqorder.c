#include "app/http3/request/h3req/reqorder.h"

#include "app/http3/core/h3/frame.h"

/* RFC 9114 4.1. Next state per (current state, frame), 0 meaning the frame is
 * not allowed there. Column 0 is HEADERS, column 1 is DATA. */
static const int next_headers[] = {
    [QUIC_H3REQ_ORDER_START]    = QUIC_H3REQ_ORDER_HEADERS,
    [QUIC_H3REQ_ORDER_HEADERS]  = QUIC_H3REQ_ORDER_TRAILERS,
    [QUIC_H3REQ_ORDER_DATA]     = QUIC_H3REQ_ORDER_TRAILERS,
    [QUIC_H3REQ_ORDER_TRAILERS] = 0,
};
static const int next_data[] = {
    [QUIC_H3REQ_ORDER_START]    = 0,
    [QUIC_H3REQ_ORDER_HEADERS]  = QUIC_H3REQ_ORDER_DATA,
    [QUIC_H3REQ_ORDER_DATA]     = QUIC_H3REQ_ORDER_DATA,
    [QUIC_H3REQ_ORDER_TRAILERS] = 0,
};

void quic_h3req_order_init(quic_h3req_order_state *s) {
  *s = QUIC_H3REQ_ORDER_START;
}

/* Pick the transition row for a frame type; null payload-only frames other
 * than HEADERS/DATA are not part of the request message and are rejected. */
static const int *row_for(u64 frame_type) {
  if (frame_type == QUIC_H3_FRAME_HEADERS) return next_headers;
  if (frame_type == QUIC_H3_FRAME_DATA) return next_data;
  return 0;
}

int quic_h3req_order_accept(quic_h3req_order_state *s, u64 frame_type) {
  const int *row = row_for(frame_type);
  if (!row || !row[*s]) return 0;
  *s = row[*s];
  return 1;
}

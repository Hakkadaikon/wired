#include "app/http3/request/h3req/reqorder.h"

#include "app/http3/core/h3/frame.h"

/* RFC 9114 4.1. Next state per (current state, frame), 0 meaning the frame is
 * not allowed there. Column 0 is HEADERS, column 1 is DATA. */
static const int next_headers[] = {
    [H3REQ_ORDER_START]    = H3REQ_ORDER_HEADERS,
    [H3REQ_ORDER_HEADERS]  = H3REQ_ORDER_TRAILERS,
    [H3REQ_ORDER_DATA]     = H3REQ_ORDER_TRAILERS,
    [H3REQ_ORDER_TRAILERS] = 0,
};
static const int next_data[] = {
    [H3REQ_ORDER_START]    = 0,
    [H3REQ_ORDER_HEADERS]  = H3REQ_ORDER_DATA,
    [H3REQ_ORDER_DATA]     = H3REQ_ORDER_DATA,
    [H3REQ_ORDER_TRAILERS] = 0,
};

void h3req_order_init(h3req_order_state* s) { *s = H3REQ_ORDER_START; }

/* Pick the transition row for a frame type; null payload-only frames other
 * than HEADERS/DATA are not part of the request message and are rejected. */
static const int* row_for(u64 frame_type) {
  if (frame_type == H3_FRAME_HEADERS) return next_headers;
  if (frame_type == H3_FRAME_DATA) return next_data;
  return 0;
}

int h3req_order_accept(h3req_order_state* s, u64 frame_type) {
  const int* row = row_for(frame_type);
  if (!row || !row[*s]) return 0;
  *s = row[*s];
  return 1;
}

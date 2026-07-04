#ifndef QUIC_H3REQ_REQORDER_H
#define QUIC_H3REQ_REQORDER_H

#include "common/platform/sys/syscall.h"

/* RFC 9114 4.1. A request stream carries, in order: a leading HEADERS frame,
 * then zero or more DATA frames, then an optional trailing HEADERS frame.
 * Anything else -- a leading DATA, a third HEADERS, DATA after the trailer --
 * is an H3_FRAME_UNEXPECTED ordering violation. */

typedef enum {
  QUIC_H3REQ_ORDER_START = 0, /* expecting the leading HEADERS */
  QUIC_H3REQ_ORDER_HEADERS,   /* leading HEADERS seen */
  QUIC_H3REQ_ORDER_DATA,      /* at least one DATA seen */
  QUIC_H3REQ_ORDER_TRAILERS   /* trailing HEADERS seen; nothing more */
} quic_h3req_order_state;

void quic_h3req_order_init(quic_h3req_order_state* s);

/* Feed the next frame type. Returns 1 and advances *s if allowed, else 0
 * (leaving *s unchanged) on an ordering violation. */
int quic_h3req_order_accept(quic_h3req_order_state* s, u64 frame_type);

#endif

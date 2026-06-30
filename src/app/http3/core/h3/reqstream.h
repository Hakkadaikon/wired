#ifndef QUIC_H3_REQSTREAM_H
#define QUIC_H3_REQSTREAM_H

#include "common/platform/sys/syscall.h"

/* RFC 9114 4.1. A request/response stream carries, in order: a HEADERS frame
 * (the header section), then zero or more DATA frames, then an optional
 * trailing HEADERS frame (the trailer section). Any other ordering -- DATA or
 * trailers before the leading HEADERS, a third HEADERS, or DATA after the
 * trailer -- is an H3_FRAME_UNEXPECTED violation. */

typedef enum {
  QUIC_H3_REQ_START = 0, /* nothing received; expecting leading HEADERS */
  QUIC_H3_REQ_HEADERS,   /* leading HEADERS seen; DATA or trailer may follow */
  QUIC_H3_REQ_DATA,      /* at least one DATA seen */
  QUIC_H3_REQ_TRAILERS   /* trailing HEADERS seen; nothing more allowed */
} quic_h3_req_state;

/* Feed the next frame type on a request stream. Returns 1 if the frame is
 * allowed in the current state (and advances *state), 0 on a FRAME_UNEXPECTED
 * ordering violation (state is left unchanged). */
int quic_h3_reqstream_frame(quic_h3_req_state *state, u64 frame_type);

#endif

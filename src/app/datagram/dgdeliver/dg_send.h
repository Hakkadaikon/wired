#ifndef DGDELIVER_DG_SEND_H
#define DGDELIVER_DG_SEND_H

#include "common/bytes/span/span.h"

/** How a DATAGRAM frame is framed and bounded. with_length picks type 0x31
 * (explicit length) over 0x30 (data to packet end); max_frame_size is the
 * peer's max_datagram_frame_size transport parameter. */
typedef struct {
  int with_length;
  u64 max_frame_size;
} dgdeliver_opts;

/* RFC 9221 5: build a DATAGRAM frame for immediate delivery (no queueing, no
 * retransmit tracking by the caller). The whole frame must fit the peer's
 * max_frame_size; otherwise 0. On success writes the frame into out (length
 * in out->len), returning 1. */
int dgdeliver_frame(wired_span data, const dgdeliver_opts* o, wired_obuf* out);

#endif

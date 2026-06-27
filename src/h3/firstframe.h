#ifndef QUIC_H3_FIRSTFRAME_H
#define QUIC_H3_FIRSTFRAME_H

#include "sys/syscall.h"
#include "h3/frame_permit.h"

/* RFC 9114 6.2.1. The first frame on the control stream must be SETTINGS; the
 * first frame on a request stream must be HEADERS. Any other leading frame
 * type is a violation (H3_MISSING_SETTINGS on control, H3_FRAME_UNEXPECTED on
 * a request stream). */


/* 1 if frame_type is allowed as the first frame on a stream of stream_kind,
 * else 0. */
int quic_h3_first_frame_ok(int stream_kind, u64 frame_type);

#endif

#ifndef QUIC_FRAME_STREAM_BOUNDS_H
#define QUIC_FRAME_STREAM_BOUNDS_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 19.8 / 4.5: a STREAM frame's final size (offset + length) must not
 * exceed 2^62-1; otherwise FRAME_ENCODING_ERROR. */

#define QUIC_MAX_OFFSET ((u64)1 << 62) /* exclusive upper bound (2^62) */

/* Returns 1 if offset + length stays within [0, 2^62-1], 0 otherwise. */
int quic_stream_bounds_ok(u64 offset, u64 length);

#endif

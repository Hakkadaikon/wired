#ifndef QUIC_STREAM_STREAM_LIMIT_H
#define QUIC_STREAM_STREAM_LIMIT_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 4.6: a MAX_STREAMS / initial_max_streams value of N permits the
 * peer to open streams with sequence indices 0..N-1 of that type. The highest
 * permitted stream ID is therefore the ID of index N-1 for the type selected
 * by is_server / is_uni. A value of 0 permits no streams. The value must not
 * exceed 2^60 (a larger value is a FRAME_ENCODING_ERROR / illegal stream ID). */

#define QUIC_MAX_STREAMS_LIMIT (((u64)1) << 60)

/* Whether a MAX_STREAMS value is within the legal range (<= 2^60). */
int quic_stream_max_streams_ok(u64 max_streams);

/* Highest stream ID the peer may open given max_streams of the selected type.
 * Returns 1 and writes *out on success; returns 0 when max_streams is 0 (no
 * stream permitted) or exceeds 2^60. */
int quic_stream_max_id(int is_server, int is_uni, u64 max_streams, u64 *out);

#endif

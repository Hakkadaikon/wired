#ifndef QUIC_FLOW_STREAMS_H
#define QUIC_FLOW_STREAMS_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 4.6: an endpoint limits how many streams its peer may open of each
 * type via the initial_max_streams transport parameters and MAX_STREAMS
 * frames. A peer opening a stream with an index at or above the limit is a
 * STREAM_LIMIT_ERROR. The limit counts streams, not a byte offset. */

typedef struct {
    u64 limit;   /* maximum number of streams the peer may open */
    u64 opened;  /* how many have been opened so far */
} quic_streams;

void quic_streams_init(quic_streams *s, u64 limit);

/* Raise the limit (MAX_STREAMS is only allowed to increase it). Returns 1 if
 * applied, 0 if the new value is not larger (ignored, never lowered). */
int quic_streams_set_max(quic_streams *s, u64 new_limit);

/* Whether the peer may open a stream with the given 0-based type index:
 * permitted only when index < limit. */
int quic_streams_may_open(const quic_streams *s, u64 index);

/* Record that one more stream was opened. */
void quic_streams_opened(quic_streams *s);

/* Observe a stream at 0-based type index: opening stream N implicitly opens
 * every lower-numbered stream of the same type (RFC 9000 3.2). Advances the
 * opened count to cover index when it is higher. */
void quic_streams_observe(quic_streams *s, u64 index);

#endif

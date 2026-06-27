#include "frame/stream_bounds.h"

/* RFC 9000 4.5: offset + length must be <= 2^62-1. The sum can wrap past
 * 2^64, so test each operand against the remaining headroom instead. */
int quic_stream_bounds_ok(u64 offset, u64 length)
{
    u64 limit = QUIC_MAX_OFFSET - 1; /* 2^62-1 */
    if (offset > limit) return 0;
    return length <= limit - offset;
}

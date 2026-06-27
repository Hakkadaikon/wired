#include "flow/streams.h"

void quic_streams_init(quic_streams *s, u64 limit)
{
    s->limit = limit;
    s->opened = 0;
}

int quic_streams_set_max(quic_streams *s, u64 new_limit)
{
    if (new_limit <= s->limit) return 0; /* MAX_STREAMS never lowers the limit */
    s->limit = new_limit;
    return 1;
}

int quic_streams_may_open(const quic_streams *s, u64 index)
{
    return index < s->limit; /* index at or above the limit is a violation */
}

void quic_streams_opened(quic_streams *s)
{
    s->opened++;
}

void quic_streams_observe(quic_streams *s, u64 index)
{
    u64 needed = index + 1; /* streams 0..index are now open */
    if (needed > s->opened) s->opened = needed;
}

#include "stream/stream_limit.h"
#include "stream/stream_id.h"

int quic_stream_max_streams_ok(u64 max_streams)
{
    return max_streams <= QUIC_MAX_STREAMS_LIMIT;
}

int quic_stream_max_id(int is_server, int is_uni, u64 max_streams, u64 *out)
{
    if (max_streams == 0) return 0;              /* no stream permitted */
    if (!quic_stream_max_streams_ok(max_streams)) return 0;
    *out = quic_stream_id(is_server, is_uni, max_streams - 1);
    return 1;
}

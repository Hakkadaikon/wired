#include "stream/stream_id.h"

int quic_stream_is_client_initiated(u64 id)
{
    return (id & QUIC_STREAM_INITIATOR_BIT) == 0;
}

int quic_stream_is_uni(u64 id)
{
    return (id & QUIC_STREAM_DIR_BIT) != 0;
}

u64 quic_stream_id(int is_server, int is_uni, u64 index)
{
    u64 low = (is_server ? QUIC_STREAM_INITIATOR_BIT : 0) |
              (is_uni ? QUIC_STREAM_DIR_BIT : 0);
    return (index << 2) | low; /* sequence in the high bits, type in the low 2 */
}

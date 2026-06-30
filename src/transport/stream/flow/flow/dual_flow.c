#include "transport/stream/flow/flow/dual_flow.h"

/* RFC 9000 4.1 */
int quic_dual_flow_ok(u64 stream_used, u64 stream_max,
                      u64 conn_used, u64 conn_max)
{
    return stream_used <= stream_max && conn_used <= conn_max;
}

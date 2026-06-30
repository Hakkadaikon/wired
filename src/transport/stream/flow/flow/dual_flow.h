#ifndef QUIC_FLOW_DUAL_FLOW_H
#define QUIC_FLOW_DUAL_FLOW_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 4.1: each byte counts against both the stream limit and the
 * connection limit. Accepting data requires staying within both. */

/* Whether stream_used and conn_used are each within their limits. Returns 1
 * only when stream_used <= stream_max and conn_used <= conn_max. */
int quic_dual_flow_ok(u64 stream_used, u64 stream_max,
                      u64 conn_used, u64 conn_max);

#endif

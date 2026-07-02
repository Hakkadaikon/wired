#include "transport/stream/flow/flow/dual_flow.h"

/* RFC 9000 4.1 */
int quic_dual_flow_ok(
    const quic_flow_usage *stream, const quic_flow_usage *conn) {
  return stream->used <= stream->max && conn->used <= conn->max;
}

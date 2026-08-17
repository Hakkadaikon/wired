#include "transport/stream/flow/flow/dual_flow.h"

/* RFC 9000 4.1 */
int dual_flow_ok(const flow_usage* stream, const flow_usage* conn) {
  return stream->used <= stream->max && conn->used <= conn->max;
}

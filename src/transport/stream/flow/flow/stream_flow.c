#include "transport/stream/flow/flow/stream_flow.h"

/* RFC 9000 4.1 */
void quic_stream_flow_init(quic_stream_flow *s, u64 window) {
  s->consumed        = 0;
  s->window          = window;
  s->max_stream_data = window;
}

/* RFC 9000 4.1 */
u64 quic_stream_flow_consume(quic_stream_flow *s, u64 n) {
  s->consumed += n;
  s->max_stream_data = s->consumed + s->window;
  return s->max_stream_data;
}

/* RFC 9000 4.1 */
int quic_stream_flow_violation(u64 received, u64 max_stream_data) {
  return received > max_stream_data;
}

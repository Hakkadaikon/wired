#include "transport/stream/flow/flow/credit.h"

/* RFC 9000 4.1 */
void quic_flow_credit_init(quic_flow_credit *c, u64 initial_max) {
  c->consumed = 0;
  c->window   = initial_max;
  c->max_data = initial_max;
}

/* RFC 9000 4.1 */
u64 quic_flow_credit_consume(quic_flow_credit *c, u64 n) {
  c->consumed += n;
  c->max_data = c->consumed + c->window;
  return c->max_data;
}

/* RFC 9000 4.1 */
int quic_flow_credit_violation(const quic_flow_credit *c, u64 received_total) {
  return received_total > c->max_data;
}

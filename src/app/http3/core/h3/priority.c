#include "app/http3/core/h3/priority.h"

/* RFC 9218 4.1: defaults are urgency 3, non-incremental. */
void quic_h3_priority_init(quic_h3_priority* p) {
  p->urgency     = QUIC_H3_URGENCY_DEFAULT;
  p->incremental = 0;
}

/* RFC 9218 4.1: a lower urgency value indicates higher priority. */
int quic_h3_priority_higher(u8 urg_a, u8 urg_b) { return urg_a < urg_b; }

/* RFC 9218 4.1: urgency ranges 0..7. */
int quic_h3_urgency_valid(u8 u) { return u <= QUIC_H3_URGENCY_MAX; }

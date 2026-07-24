#include "app/http3/core/h3/pushid.h"

void quic_h3_push_init(quic_h3_push_state* s) { s->max = 0; }

int quic_h3_push_set_max(quic_h3_push_state* s, u64 max) {
  if (max < s->max) return 0; /* RFC 9114 4.6: must not reduce */
  s->max = max;
  return 1;
}

int quic_h3_push_allowed(const quic_h3_push_state* s, u64 id) {
  return id < s->max;
}

int quic_h3_push_cancel_ok(const quic_h3_push_state* s, u64 id) {
  return quic_h3_push_allowed(s, id);
}

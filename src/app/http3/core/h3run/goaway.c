#include "app/http3/core/h3run/goaway.h"

int quic_h3_goaway_ok(quic_h3_goaway_state* state, u64 id) {
  if (state->seen && id > state->last) return 0; /* RFC 9114 5.2: H3_ID_ERROR */
  state->seen = 1;
  state->last = id;
  return 1;
}

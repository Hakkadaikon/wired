#include "app/http3/core/h3/pushid.h"

void h3_push_init(h3_push_state* s) { s->max = 0; }

int h3_push_set_max(h3_push_state* s, u64 max) {
  if (max < s->max) return 0; /* RFC 9114 4.6: must not reduce */
  s->max = max;
  return 1;
}

int h3_push_allowed(const h3_push_state* s, u64 id) { return id < s->max; }

int h3_push_cancel_ok(const h3_push_state* s, u64 id) {
  return h3_push_allowed(s, id);
}

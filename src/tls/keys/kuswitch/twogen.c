#include "tls/keys/kuswitch/twogen.h"

#include "common/bytes/util/bytes.h"

void kuswitch_init(kuswitch_state* state, const initial_keys* gen0) {
  state->cur        = *gen0;
  state->generation = 0;
  state->have_old   = 0;
}

void kuswitch_rotate(kuswitch_state* state, const initial_keys* next) {
  /* RFC 9001 6.3 */
  state->old = state->cur;
  state->cur = *next;
  state->generation++;
  state->have_old = 1;
}

void kuswitch_discard_old(kuswitch_state* state) {
  /* RFC 9001 6.5: discarded means gone from memory, not just unused */
  state->have_old = 0;
  bytes_wipe(&state->old, sizeof state->old);
}

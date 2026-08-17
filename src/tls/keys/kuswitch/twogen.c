#include "tls/keys/kuswitch/twogen.h"

#include "tls/keys/keyupdate/keyphase.h"

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

/* 1 if recv_phase_bit names the current generation. */
static int wants_current(const kuswitch_state* state, int recv_phase_bit) {
  return recv_phase_bit == keyphase_bit(state->generation);
}

int kuswitch_key_for_phase(
    const kuswitch_state* state,
    int                   recv_phase_bit,
    const initial_keys**  keys) {
  /* RFC 9001 6.3 */
  if (wants_current(state, recv_phase_bit)) {
    *keys = &state->cur;
    return 1;
  }
  if (!state->have_old) return 0;
  *keys = &state->old;
  return 1;
}

void kuswitch_discard_old(kuswitch_state* state) {
  /* RFC 9001 6.5 */
  state->have_old = 0;
}

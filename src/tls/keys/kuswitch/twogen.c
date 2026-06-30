#include "tls/keys/kuswitch/twogen.h"

#include "tls/keys/keyupdate/keyphase.h"

void quic_kuswitch_init(
    quic_kuswitch_state *state, const quic_initial_keys *gen0) {
  state->cur        = *gen0;
  state->generation = 0;
  state->have_old   = 0;
}

void quic_kuswitch_rotate(
    quic_kuswitch_state *state, const quic_initial_keys *next) {
  /* RFC 9001 6.3 */
  state->old = state->cur;
  state->cur = *next;
  state->generation++;
  state->have_old = 1;
}

/* 1 if recv_phase_bit names the current generation. */
static int wants_current(const quic_kuswitch_state *state, int recv_phase_bit) {
  return recv_phase_bit == quic_keyphase_bit(state->generation);
}

int quic_kuswitch_key_for_phase(
    const quic_kuswitch_state *state,
    int                        recv_phase_bit,
    const quic_initial_keys  **keys) {
  /* RFC 9001 6.3 */
  if (wants_current(state, recv_phase_bit)) {
    *keys = &state->cur;
    return 1;
  }
  if (!state->have_old) return 0;
  *keys = &state->old;
  return 1;
}

void quic_kuswitch_discard_old(quic_kuswitch_state *state) {
  /* RFC 9001 6.5 */
  state->have_old = 0;
}

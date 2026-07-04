#include "app/http3/core/h3run/settings_seq.h"

int quic_h3_settings_first(
    quic_h3_settings_state* state, u64 first_frame_type) {
  if (state->settings_done) return 0; /* RFC 9114 7.2.4: 2nd SETTINGS */
  if (first_frame_type != QUIC_H3_FRAME_SETTINGS)
    return 0; /* H3_MISSING_SETTINGS */
  state->settings_done = 1;
  return 1;
}

#include "app/http3/core/h3run/control.h"

usz quic_h3run_control_open(u8 *buf, usz cap) {
  if (cap < 1) return 0;
  buf[0] = 0x00; /* RFC 9114 6.2.1: control stream type */
  return 1;
}

int quic_h3_control_seen(quic_h3_control_state *state) {
  if (state->count) return 0; /* RFC 9114 6.2.1: 2nd control stream */
  state->count = 1;
  return 1;
}

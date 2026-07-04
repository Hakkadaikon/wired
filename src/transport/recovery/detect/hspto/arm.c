#include "transport/recovery/detect/hspto/arm.h"

/* RFC 9002 6.2.2.1: Handshake-space data is only relevant once Handshake
 * keys exist. */
static int handshake_armable(int handshake_inflight, int has_handshake_keys) {
  return handshake_inflight && has_handshake_keys;
}

int quic_hspto_should_arm(const quic_hspto_inputs* in) {
  /* RFC 9002 6.2.2.1: arm regardless of handshake_confirmed until ack. */
  return in->initial_inflight ||
         handshake_armable(in->handshake_inflight, in->has_handshake_keys);
}

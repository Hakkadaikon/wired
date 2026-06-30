#include "transport/recovery/detect/hspto/arm.h"

/* RFC 9002 6.2.2.1: Handshake-space data is only relevant once Handshake
 * keys exist. */
static int handshake_armable(int handshake_inflight, int has_handshake_keys) {
  return handshake_inflight && has_handshake_keys;
}

int quic_hspto_should_arm(
    int initial_inflight,
    int handshake_inflight,
    int handshake_confirmed,
    int has_handshake_keys) {
  (void)handshake_confirmed; /* RFC 9002 6.2.2.1: arm regardless until ack. */
  return initial_inflight ||
         handshake_armable(handshake_inflight, has_handshake_keys);
}

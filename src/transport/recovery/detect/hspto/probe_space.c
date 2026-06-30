#include "transport/recovery/detect/hspto/probe_space.h"

/* RFC 9002 6.2.2.1: before confirmation, prefer the lowest space with
 * in-flight data; Initial outranks Handshake. */
static int early_space(int initial_inflight, int handshake_inflight) {
  if (initial_inflight) return QUIC_HSPTO_SPACE_INITIAL;
  if (handshake_inflight) return QUIC_HSPTO_SPACE_HANDSHAKE;
  return QUIC_HSPTO_SPACE_APPLICATION;
}

int quic_hspto_probe_space(
    int initial_inflight, int handshake_inflight, int handshake_confirmed) {
  if (handshake_confirmed) return QUIC_HSPTO_SPACE_APPLICATION;
  return early_space(initial_inflight, handshake_inflight);
}

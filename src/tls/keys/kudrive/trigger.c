#include "tls/keys/kudrive/trigger.h"

/* RFC 9001 6.1: confirmed gate AND threshold reached. The compound condition
 * lives here so the public function carries no inline branch. */
static int at_limit(u64 sent, u64 threshold, int confirmed) {
  return confirmed && sent >= threshold;
}

int quic_kudrive_should_initiate(
    u64 packets_sent_in_phase, u64 update_threshold, int handshake_confirmed) {
  return at_limit(packets_sent_in_phase, update_threshold, handshake_confirmed);
}

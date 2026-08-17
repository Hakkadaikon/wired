#include "crypto/kdf/keys/promote.h"

/* RFC 9001 4.1.4. */

int key_promote_ok(int current_max_level, int new_level) {
  return new_level == current_max_level + 1;
}

int key_send_level(int handshake_complete, int handshake_confirmed) {
  /* RFC 9001 4.9: confirmation implies completion; either way 1-RTT. */
  if (handshake_complete || handshake_confirmed) return LEVEL_ONERTT;
  return LEVEL_HANDSHAKE;
}

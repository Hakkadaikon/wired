#include "crypto/kdf/keys/discard_driver.h"

/* RFC 9001 4.9. */

int key_should_discard_handshake(int handshake_confirmed) {
  return handshake_confirmed != 0;
}

int keyset_discard(keyset* state, int level) {
  if (level < 0 || level >= KEYSET_LEVELS) {
    return 0;
  }
  state->installed[level] = 0;
  return 1;
}

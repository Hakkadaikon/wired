#include "crypto/kdf/keys/discard_driver.h"

/* RFC 9001 4.9.1. */

int quic_key_should_discard_initial(int handshake_keys_installed) {
  return handshake_keys_installed != 0;
}

int quic_key_should_discard_handshake(int handshake_confirmed) {
  return handshake_confirmed != 0;
}

int quic_keyset_discard(quic_keyset *state, int level) {
  if (level < 0 || level >= QUIC_KEYSET_LEVELS) return 0;
  state->installed[level] = 0;
  return 1;
}

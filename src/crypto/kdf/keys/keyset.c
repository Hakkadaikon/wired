#include "crypto/kdf/keys/keyset.h"

/* RFC 9001 4. */

static int quic_level_valid(int level) {
  return level >= 0 && level < QUIC_KEYSET_LEVELS;
}

void quic_keyset_init(quic_keyset* state) {
  for (int i = 0; i < QUIC_KEYSET_LEVELS; i++) state->installed[i] = 0;
}

int quic_keyset_install(
    quic_keyset* state, int level, const quic_initial_keys* keys) {
  if (!quic_level_valid(level)) return 0;
  state->keys[level]      = *keys;
  state->installed[level] = 1;
  return 1;
}

int quic_keyset_for_level(
    const quic_keyset* state, int level, const quic_initial_keys** out) {
  if (!quic_level_valid(level)) return 0;
  if (!state->installed[level]) return 0;
  *out = &state->keys[level];
  return 1;
}

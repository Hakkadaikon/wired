#include "crypto/kdf/keys/keyset.h"

/* RFC 9001 4. */

static int level_valid(int level) {
  return level >= 0 && level < KEYSET_LEVELS;
}

void keyset_init(keyset* state) {
  for (int i = 0; i < KEYSET_LEVELS; i++) state->installed[i] = 0;
}

int keyset_install(keyset* state, int level, const initial_keys* keys) {
  if (!level_valid(level)) return 0;
  state->keys[level]      = *keys;
  state->installed[level] = 1;
  return 1;
}

int keyset_for_level(const keyset* state, int level, const initial_keys** out) {
  if (!level_valid(level)) return 0;
  if (!state->installed[level]) return 0;
  *out = &state->keys[level];
  return 1;
}

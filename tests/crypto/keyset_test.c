#include "test.h"

/* RFC 9001 4: install/fetch round-trips per level; un-installed levels and
 * out-of-range levels report not-available. */
void test_keyset(void) {
  keyset st;
  keyset_init(&st);

  const initial_keys* out = 0;
  CHECK(keyset_for_level(&st, LEVEL_INITIAL, &out) == 0);

  initial_keys k;
  for (int i = 0; i < INITIAL_KEY; i++) k.key[i] = (u8)(i + 1);

  CHECK(keyset_install(&st, LEVEL_HANDSHAKE, &k) == 1);
  CHECK(keyset_for_level(&st, LEVEL_HANDSHAKE, &out) == 1);
  CHECK(out->key[0] == 1);
  CHECK(out->key[INITIAL_KEY - 1] == INITIAL_KEY);

  CHECK(keyset_for_level(&st, LEVEL_INITIAL, &out) == 0);

  CHECK(keyset_install(&st, 3, &k) == 0);
  CHECK(keyset_install(&st, -1, &k) == 0);
  CHECK(keyset_for_level(&st, 3, &out) == 0);
}

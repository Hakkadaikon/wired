#include "test.h"

/* RFC 9001 4.9.1: discard Initial once Handshake keys exist, Handshake once
 * confirmed; after discard the level is no longer fetchable. */
void test_discard_driver(void) {
  CHECK(key_should_discard_initial(0) == 0);
  CHECK(key_should_discard_initial(1) == 1);
  CHECK(key_should_discard_handshake(0) == 0);
  CHECK(key_should_discard_handshake(1) == 1);

  keyset st;
  keyset_init(&st);

  initial_keys k;
  for (int i = 0; i < INITIAL_KEY; i++) k.key[i] = (u8)i;

  keyset_install(&st, LEVEL_INITIAL, &k);
  const initial_keys* out = 0;
  CHECK(keyset_for_level(&st, LEVEL_INITIAL, &out) == 1);

  CHECK(keyset_discard(&st, LEVEL_INITIAL) == 1);
  CHECK(keyset_for_level(&st, LEVEL_INITIAL, &out) == 0);

  CHECK(keyset_discard(&st, 3) == 0);
}

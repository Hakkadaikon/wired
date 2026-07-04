#include "test.h"

/* RFC 9001 4.9.1: discard Initial once Handshake keys exist, Handshake once
 * confirmed; after discard the level is no longer fetchable. */
void test_discard_driver(void) {
  CHECK(quic_key_should_discard_initial(0) == 0);
  CHECK(quic_key_should_discard_initial(1) == 1);
  CHECK(quic_key_should_discard_handshake(0) == 0);
  CHECK(quic_key_should_discard_handshake(1) == 1);

  quic_keyset st;
  quic_keyset_init(&st);

  quic_initial_keys k;
  for (int i = 0; i < QUIC_INITIAL_KEY; i++) k.key[i] = (u8)i;

  quic_keyset_install(&st, QUIC_LEVEL_INITIAL, &k);
  const quic_initial_keys* out = 0;
  CHECK(quic_keyset_for_level(&st, QUIC_LEVEL_INITIAL, &out) == 1);

  CHECK(quic_keyset_discard(&st, QUIC_LEVEL_INITIAL) == 1);
  CHECK(quic_keyset_for_level(&st, QUIC_LEVEL_INITIAL, &out) == 0);

  CHECK(quic_keyset_discard(&st, 3) == 0);
}

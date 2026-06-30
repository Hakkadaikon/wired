#include "test.h"

/* RFC 9001 4: install/fetch round-trips per level; un-installed levels and
 * out-of-range levels report not-available. */
void test_keyset(void) {
  quic_keyset st;
  quic_keyset_init(&st);

  const quic_initial_keys *out = 0;
  CHECK(quic_keyset_for_level(&st, QUIC_LEVEL_INITIAL, &out) == 0);

  quic_initial_keys k;
  for (int i = 0; i < QUIC_INITIAL_KEY; i++) k.key[i] = (u8)(i + 1);

  CHECK(quic_keyset_install(&st, QUIC_LEVEL_HANDSHAKE, &k) == 1);
  CHECK(quic_keyset_for_level(&st, QUIC_LEVEL_HANDSHAKE, &out) == 1);
  CHECK(out->key[0] == 1);
  CHECK(out->key[QUIC_INITIAL_KEY - 1] == QUIC_INITIAL_KEY);

  CHECK(quic_keyset_for_level(&st, QUIC_LEVEL_INITIAL, &out) == 0);

  CHECK(quic_keyset_install(&st, 3, &k) == 0);
  CHECK(quic_keyset_install(&st, -1, &k) == 0);
  CHECK(quic_keyset_for_level(&st, 3, &out) == 0);
}

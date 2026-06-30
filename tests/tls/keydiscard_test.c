#include "test.h"

/* Initial keys go once Handshake keys exist; Handshake keys go once the
 * handshake is confirmed. */
void test_keydiscard(void) {
  CHECK(quic_key_discard_initial(0) == 0);
  CHECK(quic_key_discard_initial(1) == 1);

  CHECK(quic_key_discard_handshake(0) == 0);
  CHECK(quic_key_discard_handshake(1) == 1);
}

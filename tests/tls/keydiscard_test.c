#include "test.h"

/* Initial keys go once Handshake keys exist; Handshake keys go once the
 * handshake is confirmed. */
void test_keydiscard(void) {
  CHECK(key_discard_initial(0) == 0);
  CHECK(key_discard_initial(1) == 1);

  CHECK(key_discard_handshake(0) == 0);
  CHECK(key_discard_handshake(1) == 1);
}

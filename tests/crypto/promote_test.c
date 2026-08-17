#include "test.h"

/* RFC 9001 4.1.4: keys promote one level at a time; skipping a level (Initial
 * straight to 1-RTT) is rejected. Send level follows handshake completion. */
void test_promote(void) {
  CHECK(key_promote_ok(LEVEL_INITIAL, LEVEL_HANDSHAKE) == 1);
  CHECK(key_promote_ok(LEVEL_HANDSHAKE, LEVEL_ONERTT) == 1);

  /* Initial -> 1-RTT skips Handshake. */
  CHECK(key_promote_ok(LEVEL_INITIAL, LEVEL_ONERTT) == 0);
  /* No going backwards or standing still. */
  CHECK(key_promote_ok(LEVEL_HANDSHAKE, LEVEL_HANDSHAKE) == 0);
  CHECK(key_promote_ok(LEVEL_ONERTT, LEVEL_HANDSHAKE) == 0);

  CHECK(key_send_level(0, 0) == LEVEL_HANDSHAKE);
  CHECK(key_send_level(1, 0) == LEVEL_ONERTT);
  CHECK(key_send_level(1, 1) == LEVEL_ONERTT);
}

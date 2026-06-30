#include "test.h"

/* RFC 9001 4.1.4: keys promote one level at a time; skipping a level (Initial
 * straight to 1-RTT) is rejected. Send level follows handshake completion. */
void test_promote(void) {
  CHECK(quic_key_promote_ok(QUIC_LEVEL_INITIAL, QUIC_LEVEL_HANDSHAKE) == 1);
  CHECK(quic_key_promote_ok(QUIC_LEVEL_HANDSHAKE, QUIC_LEVEL_ONERTT) == 1);

  /* Initial -> 1-RTT skips Handshake. */
  CHECK(quic_key_promote_ok(QUIC_LEVEL_INITIAL, QUIC_LEVEL_ONERTT) == 0);
  /* No going backwards or standing still. */
  CHECK(quic_key_promote_ok(QUIC_LEVEL_HANDSHAKE, QUIC_LEVEL_HANDSHAKE) == 0);
  CHECK(quic_key_promote_ok(QUIC_LEVEL_ONERTT, QUIC_LEVEL_HANDSHAKE) == 0);

  CHECK(quic_key_send_level(0, 0) == QUIC_LEVEL_HANDSHAKE);
  CHECK(quic_key_send_level(1, 0) == QUIC_LEVEL_ONERTT);
  CHECK(quic_key_send_level(1, 1) == QUIC_LEVEL_ONERTT);
}

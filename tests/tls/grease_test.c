#include "test.h"

/* The grease_quic_bit parameter round-trips with an empty value. */
static void test_grease_param(void) {
  u8  buf[8];
  usz w = quic_grease_encode(buf, sizeof(buf));
  CHECK(w != 0);
  CHECK(quic_grease_decode(buf, w) == w);

  /* a non-empty value is rejected */
  buf[w - 1] = 1; /* set the length byte to 1 */
  CHECK(quic_grease_decode(buf, w + 1) == 0);
}

/* When the peer greases, a cleared QUIC Bit is accepted; otherwise the bit
 * must be set. */
static void test_grease_accept(void) {
  /* peer does not grease: QUIC Bit (0x40) must be set */
  CHECK(quic_grease_accept_byte0(0xC0, 0) == 1); /* bit set */
  CHECK(quic_grease_accept_byte0(0x80, 0) == 0); /* bit cleared, refused */
  /* peer greases: either value is accepted */
  CHECK(quic_grease_accept_byte0(0xC0, 1) == 1);
  CHECK(quic_grease_accept_byte0(0x80, 1) == 1); /* cleared but accepted */
}

void test_grease(void) {
  test_grease_param();
  test_grease_accept();
}

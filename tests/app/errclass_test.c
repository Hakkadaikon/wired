#include "app/http3/core/h3/frame.h"
#include "test.h"

/* The defined block 0x0100..0x0110 is known; just outside it is not. */
static void test_known_block(void) {
  CHECK(quic_h3_error_is_known(QUIC_H3_NO_ERROR) == 1); /* 0x0100 low */
  CHECK(
      quic_h3_error_is_known(QUIC_H3_VERSION_FALLBACK) == 1); /* 0x0110 high */
  CHECK(quic_h3_error_is_known(QUIC_H3_FRAME_UNEXPECTED) == 1);
  CHECK(quic_h3_error_is_known(0x00ff) == 0); /* just below */
  CHECK(quic_h3_error_is_known(0x0111) == 0); /* just above */
  CHECK(quic_h3_error_is_known(0) == 0);
}

/* Reserved (grease) points are recognized and are not "known" codes. */
static void test_reserved(void) {
  CHECK(quic_h3_error_is_reserved(0x21) == 1); /* N=0 */
  CHECK(quic_h3_error_is_reserved(0x21 + 0x1f * 9) == 1);
  CHECK(quic_h3_error_is_reserved(0x20) == 0);
  CHECK(quic_h3_error_is_known(0x21) == 0); /* reserved != known */
}

void test_errclass(void) {
  test_known_block();
  test_reserved();
}

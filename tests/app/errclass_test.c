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

/* RFC 9114 8.1 / 9114-077: quic_h3_error_send_value substitutes grease_id for
 * H3_NO_ERROR only when grease_id is non-zero, and never touches any other
 * code -- the deterministic half of "send grease with some probability" (the
 * probability itself lives in whoever picks grease_id, not here). */
static void test_error_send_value(void) {
  /* grease_id == 0: H3_NO_ERROR passes through unchanged */
  CHECK(quic_h3_error_send_value(QUIC_H3_NO_ERROR, 0) == QUIC_H3_NO_ERROR);
  /* non-zero grease_id substitutes for H3_NO_ERROR */
  {
    u64 gid = 0x21 + 0x1f * 5;
    CHECK(quic_h3_error_is_reserved(gid) == 1);
    CHECK(quic_h3_error_send_value(QUIC_H3_NO_ERROR, gid) == gid);
  }
  /* any other code is never substituted, grease_id or not */
  CHECK(
      quic_h3_error_send_value(QUIC_H3_REQUEST_CANCELLED, 0x21 + 0x1f) ==
      QUIC_H3_REQUEST_CANCELLED);
  CHECK(
      quic_h3_error_send_value(QUIC_H3_INTERNAL_ERROR, 0) ==
      QUIC_H3_INTERNAL_ERROR);
}

void test_errclass(void) {
  test_known_block();
  test_reserved();
  test_error_send_value();
}

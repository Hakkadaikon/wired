#include "test.h"

/* RFC 9000 12.2: a long header (high bit set) is fine in any position. */
static void test_coalorder_long_any(void) {
  CHECK(quic_coalesce_short_must_be_last(0xC0, 0) == 1); /* not last, ok */
  CHECK(quic_coalesce_short_must_be_last(0xC0, 1) == 1); /* last, ok */
}

/* A short header (high bit clear) is only allowed as the last packet. */
static void test_coalorder_short_last_only(void) {
  CHECK(quic_coalesce_short_must_be_last(0x40, 1) == 1); /* last, ok */
  CHECK(quic_coalesce_short_must_be_last(0x40, 0) == 0); /* not last, bad */
}

void test_coalorder(void) {
  test_coalorder_long_any();
  test_coalorder_short_last_only();
}

#include "test.h"

/* RFC 9114 5.2: GOAWAY ids are non-increasing; decreasing and equal are fine.
 */
static void test_goaway_monotonic_ok(void) {
  quic_h3_goaway_state s = {0};
  CHECK(quic_h3_goaway_ok(&s, 100) == 1); /* first */
  CHECK(quic_h3_goaway_ok(&s, 100) == 1); /* equal */
  CHECK(quic_h3_goaway_ok(&s, 40) == 1);  /* decrease */
  CHECK(quic_h3_goaway_ok(&s, 0) == 1);   /* decrease to zero */
}

/* RFC 9114 5.2: an increasing GOAWAY id is H3_ID_ERROR. */
static void test_goaway_increase_rejected(void) {
  quic_h3_goaway_state s = {0};
  CHECK(quic_h3_goaway_ok(&s, 8) == 1);
  CHECK(quic_h3_goaway_ok(&s, 12) == 0); /* increase: H3_ID_ERROR */
}

void test_h3run_goaway(void) {
  test_goaway_monotonic_ok();
  test_goaway_increase_rejected();
}

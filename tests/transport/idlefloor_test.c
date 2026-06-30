#include "test.h"

/* Effective idle never drops below 3*PTO (RFC 9000 10.1). */
static void test_idlefloor_floor(void) {
  CHECK(quic_idle_floor(100, 10) == 100); /* idle > 3*pto=30 */
  CHECK(quic_idle_floor(20, 10) == 30);   /* idle < 3*pto, floor wins */
  CHECK(quic_idle_floor(30, 10) == 30);   /* exactly equal */
  CHECK(quic_idle_floor(0, 10) == 30);    /* zero idle floored to 3*pto */
}

/* Close fires at/after the effective idle boundary, not before (RFC 9000 10.1).
 */
static void test_idlefloor_should_close(void) {
  CHECK(quic_idle_should_close(29, 30) == 0);
  CHECK(quic_idle_should_close(30, 30) == 1);
  CHECK(quic_idle_should_close(31, 30) == 1);
}

void test_idlefloor(void) {
  test_idlefloor_floor();
  test_idlefloor_should_close();
}

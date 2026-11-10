#include "test.h"

/* Effective idle never drops below 3*PTO (RFC 9000 10.1). */
static void test_idlefloor_floor(void) {
  CHECK(idle_floor(100, 10) == 100); /* idle > 3*pto=30 */
  CHECK(idle_floor(20, 10) == 30);   /* idle < 3*pto, floor wins */
  CHECK(idle_floor(30, 10) == 30);   /* exactly equal */
  CHECK(idle_floor(0, 10) == 30);    /* zero idle floored to 3*pto */
}

void test_idlefloor(void) { test_idlefloor_floor(); }

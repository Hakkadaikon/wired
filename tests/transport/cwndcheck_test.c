#include "test.h"

/* Admission: ok up to exactly cwnd, blocked one byte past. */
static void test_cwnd_can_send_boundary(void) {
  CHECK(cwnd_can_send(1000, 2000, 1000) == 1); /* fills exactly */
  CHECK(cwnd_can_send(1000, 2000, 1001) == 0); /* one byte over */
  CHECK(cwnd_can_send(2000, 2000, 0) == 1);    /* full, zero-size ok */
  CHECK(cwnd_can_send(2000, 2000, 1) == 0);    /* full, no room */
}

/* App-limited when in-flight is strictly below cwnd. */
static void test_cwnd_app_limited(void) {
  CHECK(cwnd_app_limited(500, 2000) == 1);  /* under-utilized */
  CHECK(cwnd_app_limited(2000, 2000) == 0); /* fully utilized */
  CHECK(cwnd_app_limited(2001, 2000) == 0); /* over (not app-limited) */
}

void test_cwndcheck(void) {
  test_cwnd_can_send_boundary();
  test_cwnd_app_limited();
}

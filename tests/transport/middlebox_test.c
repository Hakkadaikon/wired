#include "test.h"

static void test_initial_ok(void) {
  CHECK(!middlebox_initial_ok(1199)); /* below minimum */
  CHECK(middlebox_initial_ok(1200));  /* at minimum: ok */
  CHECK(middlebox_initial_ok(1500));  /* above minimum */
}

void test_middlebox(void) { test_initial_ok(); }

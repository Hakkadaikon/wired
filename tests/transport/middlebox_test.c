#include "test.h"

static void test_initial_ok(void) {
  CHECK(!middlebox_initial_ok(1199)); /* below minimum */
  CHECK(middlebox_initial_ok(1200));  /* at minimum: ok */
  CHECK(middlebox_initial_ok(1500));  /* above minimum */
}

static void test_port_expected(void) {
  CHECK(middlebox_port_expected(443));
  CHECK(!middlebox_port_expected(80));
  CHECK(!middlebox_port_expected(0));
}

void test_middlebox(void) {
  test_initial_ok();
  test_port_expected();
}

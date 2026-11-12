#include "test.h"

/* Budget is 3x received minus sent, clamped at zero. */
static void test_antiamp_budget(void) {
  CHECK(antiamp_budget(100, 0) == 300);
  CHECK(antiamp_budget(100, 250) == 50);
  CHECK(antiamp_budget(100, 300) == 0); /* exactly at the limit */
  CHECK(antiamp_budget(100, 301) == 0); /* over: clamped, no wrap */
  CHECK(antiamp_budget(0, 0) == 0);
}

void test_antiamp(void) { test_antiamp_budget(); }

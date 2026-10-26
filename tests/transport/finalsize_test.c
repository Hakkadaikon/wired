#include "test.h"

/* A consistent final size is accepted; data at or beyond it is rejected. */
static void test_finalsize_data(void) {
  finalsize f;
  finalsize_init(&f);
  CHECK(finalsize_data(&f, 0, 10) == 1); /* data [0,10) */
  CHECK(finalsize_set(&f, 10) == 1);     /* final size 10 matches */
  CHECK(finalsize_data(&f, 0, 10) == 1); /* still within */
  CHECK(finalsize_data(&f, 5, 10) == 0); /* reaches 15 > 10: violation */
}

/* The final size is immutable; a different value is a FINAL_SIZE_ERROR. */
static void test_finalsize_immutable(void) {
  finalsize f;
  finalsize_init(&f);
  CHECK(finalsize_set(&f, 20) == 1);
  CHECK(finalsize_set(&f, 20) == 1); /* same value ok */
  CHECK(finalsize_set(&f, 21) == 0); /* changed: violation */
}

/* A final size below data already seen is a violation. */
static void test_finalsize_below_highest(void) {
  finalsize f;
  finalsize_init(&f);
  CHECK(finalsize_data(&f, 0, 30) == 1); /* highest now 30 */
  CHECK(finalsize_set(&f, 25) == 0);     /* below 30: violation */
  CHECK(finalsize_set(&f, 30) == 1);     /* exactly the highest: ok */
}

void test_finalsize(void) {
  test_finalsize_data();
  test_finalsize_immutable();
  test_finalsize_below_highest();
}

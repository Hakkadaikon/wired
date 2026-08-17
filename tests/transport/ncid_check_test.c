#include "test.h"

void test_ncid_check(void) {
  /* retire_prior_to vs seq */
  CHECK(ncid_check(5, 0, 8) == 1);
  CHECK(ncid_check(5, 5, 8) == 1); /* equal is allowed */
  CHECK(ncid_check(5, 6, 8) == 0); /* greater is rejected */
  CHECK(ncid_check(0, 0, 8) == 1);

  /* cid_len boundaries 1..20 */
  CHECK(ncid_check(1, 0, 0) == 0);  /* zero length rejected */
  CHECK(ncid_check(1, 0, 1) == 1);  /* min */
  CHECK(ncid_check(1, 0, 20) == 1); /* max */
  CHECK(ncid_check(1, 0, 21) == 0); /* over max */
  CHECK(ncid_check(1, 0, 255) == 0);
}

#include "test.h"

void test_dosmitigate(void) {
  CHECK(dos_should_retry(100, 50) == 1); /* over threshold */
  CHECK(dos_should_retry(50, 50) == 0);  /* at threshold */
  CHECK(dos_should_retry(10, 50) == 0);  /* under threshold */

  CHECK(dos_amplification_ok(100, 300) == 1); /* exactly 3x */
  CHECK(dos_amplification_ok(100, 301) == 0); /* over 3x */
  CHECK(dos_amplification_ok(100, 0) == 1);   /* nothing sent */
  CHECK(dos_amplification_ok(0, 1) == 0);     /* 3*0 = 0 */
}

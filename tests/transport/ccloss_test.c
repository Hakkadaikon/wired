#include "test.h"

/* RFC 9002 7.3.2: sent at or before recovery_start is in recovery. */
static void test_ccloss_in_recovery(void) {
  CHECK(cc_in_recovery(50, 100) == 1);
  CHECK(cc_in_recovery(100, 100) == 1); /* boundary */
  CHECK(cc_in_recovery(101, 100) == 0);
}

void test_ccloss(void) { test_ccloss_in_recovery(); }

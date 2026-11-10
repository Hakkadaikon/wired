#include "test.h"

/* RFC 9002 A.7: a packet is newly acked only when above the prior largest. */
static void test_largestacked_newly(void) {
  CHECK(newly_acked(5, 6) == 1);
  CHECK(newly_acked(5, 5) == 0); /* boundary: equal is not new */
  CHECK(newly_acked(5, 4) == 0);
}

void test_largestacked(void) { test_largestacked_newly(); }

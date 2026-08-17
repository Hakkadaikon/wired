#include "test.h"

void test_zerortt_policy(void) {
  CHECK(zerortt_safe(1, 0) == 1); /* idempotent */
  CHECK(zerortt_safe(0, 1) == 1); /* replay protected */
  CHECK(zerortt_safe(1, 1) == 1);
  CHECK(zerortt_safe(0, 0) == 0); /* neither: unsafe */
}

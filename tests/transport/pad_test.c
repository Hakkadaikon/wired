#include "test.h"

/* Padding brings a short datagram up to 1200 bytes; larger ones need none. */
static void test_pad(void) {
  CHECK(pad_needed(0) == 1200);
  CHECK(pad_needed(200) == 1000);
  CHECK(pad_needed(1199) == 1);
  CHECK(pad_needed(1200) == 0); /* exactly the minimum */
  CHECK(pad_needed(1500) == 0); /* already large enough */
}

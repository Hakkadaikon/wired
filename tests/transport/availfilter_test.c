#include "test.h"

/* RFC 9368 3: reserved (0x?a?a?a?a) versions are not usable. */
static void test_availfilter_grease_excluded(void) {
  CHECK(verinfo_is_usable(0x0a0a0a0au) == 0);
  CHECK(verinfo_is_usable(0x1a2a3a4au) == 0);
}

/* Real versions are usable. */
static void test_availfilter_real_usable(void) {
  CHECK(verinfo_is_usable(VERSION_1) == 1);
  CHECK(verinfo_is_usable(VERSION_2) == 1);
}

void test_availfilter(void) {
  test_availfilter_grease_excluded();
  test_availfilter_real_usable();
}

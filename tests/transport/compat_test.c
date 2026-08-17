#include "test.h"

/* RFC 9369 3.1: v1 and v2 are compatible in both directions. */
static void test_v1_v2_compatible(void) {
  CHECK(version_compatible(VERSION_1, VERSION_2) == 1);
  CHECK(version_compatible(VERSION_2, VERSION_1) == 1);
}

/* RFC 9368 2.1: a known version is compatible with itself. */
static void test_self_compatible(void) {
  CHECK(version_compatible(VERSION_1, VERSION_1) == 1);
  CHECK(version_compatible(VERSION_2, VERSION_2) == 1);
}

/* An unknown version has no known compatibility, even with itself. */
static void test_unknown_incompatible(void) {
  CHECK(version_compatible(0xdeadbeefu, VERSION_1) == 0);
  CHECK(version_compatible(VERSION_1, 0xdeadbeefu) == 0);
  CHECK(version_compatible(0xdeadbeefu, 0xdeadbeefu) == 0);
}

void test_compat(void) {
  test_v1_v2_compatible();
  test_self_compatible();
  test_unknown_incompatible();
}

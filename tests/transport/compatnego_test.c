#include "test.h"

/* Compatible versions switch without a new handshake; incompatible ones
 * require one. The two predicates are complements. */
void test_compatnego(void) {
  /* v1 <-> v2 are compatible: switch ok, no retry */
  CHECK(version_compat_switch_ok(VERSION_1, VERSION_2) == 1);
  CHECK(version_needs_retry(VERSION_1, VERSION_2) == 0);

  /* same version: compatible with itself */
  CHECK(version_compat_switch_ok(VERSION_1, VERSION_1) == 1);

  /* unknown negotiated version: not compatible, needs retry */
  CHECK(version_compat_switch_ok(VERSION_1, 0xdeadbeefu) == 0);
  CHECK(version_needs_retry(VERSION_1, 0xdeadbeefu) == 1);

  /* complement holds for an unknown pair too */
  CHECK(version_compat_switch_ok(0xdeadbeefu, 0xdeadbeefu) == 0);
  CHECK(version_needs_retry(0xdeadbeefu, 0xdeadbeefu) == 1);
}

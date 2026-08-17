#include "test.h"

/* A mismatch between the version the client chose and the one the server
 * reports signals a possible downgrade attack. */
void test_downgrade(void) {
  CHECK(version_downgrade_detected(VERSION_2, VERSION_2) == 0);
  CHECK(version_downgrade_detected(VERSION_2, VERSION_1) == 1);
  CHECK(version_downgrade_detected(VERSION_1, VERSION_1) == 0);
}

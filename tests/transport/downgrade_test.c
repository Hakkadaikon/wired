#include "test.h"

/* A mismatch between the version the client chose and the one the server
 * reports signals a possible downgrade attack. */
void test_downgrade(void) {
  CHECK(version_downgrade_detected(QUIC_VERSION_2, QUIC_VERSION_2) == 0);
  CHECK(version_downgrade_detected(QUIC_VERSION_2, QUIC_VERSION_1) == 1);
  CHECK(version_downgrade_detected(QUIC_VERSION_1, QUIC_VERSION_1) == 0);
}

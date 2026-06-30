#include "test.h"

/* Migration to preferred_address needs both path validation and confirmation.
 */
static void test_prefaddr_may_migrate(void) {
  CHECK(quic_prefaddr_may_migrate(1, 1) == 1);
  CHECK(quic_prefaddr_may_migrate(0, 1) == 0); /* path not validated */
  CHECK(quic_prefaddr_may_migrate(1, 0) == 0); /* handshake not confirmed */
  CHECK(quic_prefaddr_may_migrate(0, 0) == 0);
}

/* Use the preferred_address CID only when one was supplied. */
static void test_prefaddr_use_cid(void) {
  CHECK(quic_prefaddr_use_cid(1) == 1);
  CHECK(quic_prefaddr_use_cid(0) == 0);
}

void test_prefaddr(void) {
  test_prefaddr_may_migrate();
  test_prefaddr_use_cid();
}

#include "tls/handshake/core/tls/cryptolevel.h"

#include "test.h"

/* RFC 9001 4.1.3: promoting to a higher level while the old level still has
 * received-but-undelivered bytes is a violation. */
static void test_cryptolevel_unconsumed_on_promote_true(void) {
  CHECK(cryptolevel_unconsumed_on_promote(10, 5));
  CHECK(cryptolevel_unconsumed_on_promote(1, 0));
}

/* Fully drained (or empty) levels promote cleanly. */
static void test_cryptolevel_unconsumed_on_promote_false(void) {
  CHECK(!cryptolevel_unconsumed_on_promote(10, 10));
  CHECK(!cryptolevel_unconsumed_on_promote(0, 0));
}

void test_cryptolevel(void) {
  test_cryptolevel_unconsumed_on_promote_true();
  test_cryptolevel_unconsumed_on_promote_false();
}

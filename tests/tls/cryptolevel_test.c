#include "tls/handshake/core/tls/cryptolevel.h"

#include "test.h"

/* RFC 9001 4.1.3: CRYPTO data at a superseded level extending past the
 * highest offset+len already seen at that level is a violation. */
static void test_cryptolevel_stale_extends_true(void) {
  CHECK(cryptolevel_stale_extends(10, 5, 10)); /* 5+10=15 > 10 */
  CHECK(cryptolevel_stale_extends(0, 0, 1));   /* first byte, max 0 */
}

/* Data fully within the already-seen range is not a violation. */
static void test_cryptolevel_stale_extends_false(void) {
  CHECK(!cryptolevel_stale_extends(10, 0, 10)); /* exactly reaches 10 */
  CHECK(!cryptolevel_stale_extends(10, 2, 3));  /* [2,5) within 10 */
  CHECK(!cryptolevel_stale_extends(0, 0, 0));   /* empty, nothing new */
}

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
  test_cryptolevel_stale_extends_true();
  test_cryptolevel_stale_extends_false();
  test_cryptolevel_unconsumed_on_promote_true();
  test_cryptolevel_unconsumed_on_promote_false();
}

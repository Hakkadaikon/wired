#include "test.h"

/* RFC 9001 6.4: a packet decrypting under the old key phase with a packet
 * number higher than one already seen under the new phase is a
 * KEY_UPDATE_ERROR. */
static void test_pncheck_violation(void) {
  CHECK(quic_keyupdate_pn_violates(10, 11)); /* old-key PN past new phase */
  CHECK(quic_keyupdate_pn_violates(0, 1));
}

/* An old-key packet numbered at or before the new phase's lowest PN is
 * legitimate reordering, not a violation. */
static void test_pncheck_no_violation(void) {
  CHECK(!quic_keyupdate_pn_violates(10, 10)); /* equal: not "higher" */
  CHECK(!quic_keyupdate_pn_violates(10, 5));  /* reordered, still old-key */
  CHECK(!quic_keyupdate_pn_violates(0, 0));
}

void test_pncheck(void) {
  test_pncheck_violation();
  test_pncheck_no_violation();
}

#include "test.h"

/* RFC 9001 6.1: update only after handshake confirmed and 3*PTO elapsed. */
void test_initiate(void) {
  u64 last = 1000, pto = 100; /* earliest next update at last+300 = 1300 */

  /* not confirmed: never, even long after */
  CHECK(!quic_keyupdate_may_initiate(&(quic_keyupdate_in){0, last, 5000, pto}));

  /* confirmed but 3*PTO not yet elapsed */
  CHECK(!quic_keyupdate_may_initiate(&(quic_keyupdate_in){1, last, 1299, pto}));

  /* confirmed and exactly 3*PTO elapsed: allowed */
  CHECK(quic_keyupdate_may_initiate(&(quic_keyupdate_in){1, last, 1300, pto}));

  /* confirmed and well past: allowed */
  CHECK(quic_keyupdate_may_initiate(&(quic_keyupdate_in){1, last, 2000, pto}));
}

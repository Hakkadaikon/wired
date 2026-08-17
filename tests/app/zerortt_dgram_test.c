#include "test.h"

/* RFC 9221 3: no remembered support means no 0-RTT DATAGRAM. */
static void test_no_remembered_support(void) {
  CHECK(datagram_0rtt_ok(0, 0) == 0);
  CHECK(datagram_0rtt_ok(0, 100) == 0);
}

/* A frame within the remembered limit is allowed. */
static void test_within_limit(void) {
  CHECK(datagram_0rtt_ok(1200, 1) == 1);
  CHECK(datagram_0rtt_ok(1200, 1200) == 1); /* boundary: equal */
}

/* A frame exceeding the remembered limit is rejected. */
static void test_over_limit(void) {
  CHECK(datagram_0rtt_ok(1200, 1201) == 0); /* boundary: +1 */
}

/* RFC 9221 3: accepting 0-RTT with a max_datagram_frame_size at least equal
 * to the ticket-issuing connection's value is safe -- equal (boundary) and
 * greater both pass. */
static void test_0rtt_accept_meets_or_exceeds_issued(void) {
  CHECK(datagram_0rtt_accept_ok(1200, 1200) == 1); /* boundary: equal */
  CHECK(datagram_0rtt_accept_ok(1200, 65535) == 1);
  CHECK(datagram_0rtt_accept_ok(0, 0) == 1); /* neither ever supported */
}

/* RFC 9221 3: a server that would now advertise LESS than it advertised on
 * the ticket-issuing connection MUST NOT accept 0-RTT -- a stored client
 * DATAGRAM frame within the old limit could exceed the new one. */
static void test_0rtt_accept_below_issued_rejected(void) {
  CHECK(datagram_0rtt_accept_ok(1200, 1199) == 0); /* boundary: -1 */
  CHECK(datagram_0rtt_accept_ok(65535, 0) == 0);
}

void test_zerortt_dgram(void) {
  test_no_remembered_support();
  test_within_limit();
  test_over_limit();
  test_0rtt_accept_meets_or_exceeds_issued();
  test_0rtt_accept_below_issued_rejected();
}

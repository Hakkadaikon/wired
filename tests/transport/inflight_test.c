#include "test.h"

/* RFC 9002 2: in-flight iff ack-eliciting or PADDING-bearing. */
static void test_inflight_in_flight(void) {
  CHECK(pkt_in_flight(0, 0) == 0);
  CHECK(pkt_in_flight(1, 0) == 1);
  CHECK(pkt_in_flight(0, 1) == 1);
  CHECK(pkt_in_flight(1, 1) == 1);
}

void test_inflight(void) { test_inflight_in_flight(); }

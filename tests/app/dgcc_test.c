#include "test.h"

/* RFC 9221 5.2/5.3/5.4: not flow controlled, congestion controlled, counted
 * in flight, ack-eliciting but never retransmitted. */
void test_dgcc(void) {
  CHECK(datagram_flow_controlled() == 0);
  CHECK(datagram_congestion_controlled() == 1);
  CHECK(datagram_counts_in_flight(1200) == 1200);
  CHECK(datagram_counts_in_flight(0) == 0);
  CHECK(datagram_ack_eliciting() == 1);
  CHECK(datagram_retransmittable() == 0);
}

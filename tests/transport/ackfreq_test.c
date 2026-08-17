#include "test.h"

/* RFC 9000 13.2.1: ack once two ack-eliciting packets are outstanding, or once
 * max_ack_delay has elapsed. */
void test_ackfreq(void) {
  /* nothing outstanding: never due */
  CHECK(ackgen_due(0, 1000, 25) == 0);

  /* one outstanding, within delay: not yet */
  CHECK(ackgen_due(1, 24, 25) == 0);

  /* one outstanding, delay elapsed: due */
  CHECK(ackgen_due(1, 25, 25) == 1);

  /* two outstanding: due immediately regardless of elapsed */
  CHECK(ackgen_due(2, 0, 25) == 1);
  CHECK(ackgen_due(3, 0, 25) == 1);
}

#include "test.h"

/* RFC 9000 13.2.1 / 13.2.2: ack immediately after two ack-eliciting packets,
 * else within max_ack_delay of the oldest unacked one. */
void test_ackpolicy(void) {
  ackpolicy p;
  ackpolicy_init(&p);

  /* nothing pending: no ack */
  CHECK(ackpolicy_should_ack(&p, 100, 25) == 0);

  /* one ack-eliciting packet at tick 10, delay 25: not yet, then due */
  ackpolicy_on_eliciting(&p, 10);
  CHECK(ackpolicy_should_ack(&p, 20, 25) == 0); /* 10 elapsed < 25 */
  CHECK(ackpolicy_should_ack(&p, 34, 25) == 0); /* 24 < 25 */
  CHECK(ackpolicy_should_ack(&p, 35, 25) == 1); /* 25 >= 25 */

  /* a second ack-eliciting packet triggers an immediate ack */
  ackpolicy_on_eliciting(&p, 11);
  CHECK(ackpolicy_should_ack(&p, 12, 25) == 1); /* two pending */

  /* after sending an ack, state clears */
  ackpolicy_on_ack_sent(&p);
  CHECK(ackpolicy_should_ack(&p, 1000, 25) == 0);

  /* the delay timer starts from the oldest pending packet, not the newest */
  ackpolicy_on_eliciting(&p, 50);
  ackpolicy_on_ack_sent(&p);
  ackpolicy_on_eliciting(&p, 60);               /* oldest is now tick 60 */
  CHECK(ackpolicy_should_ack(&p, 84, 25) == 0); /* 24 < 25 */
  CHECK(ackpolicy_should_ack(&p, 85, 25) == 1); /* 25 >= 25 */
}

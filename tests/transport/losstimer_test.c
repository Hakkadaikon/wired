#include "test.h"

/* RFC 9002 6.2 */
void test_losstimer(void) {
  /* no loss time: always pto_time */
  CHECK(losstimer_next(50, 100, 0) == 100);

  /* loss time earlier than pto: take loss time */
  CHECK(losstimer_next(50, 100, 1) == 50);

  /* loss time later than pto: take pto */
  CHECK(losstimer_next(150, 100, 1) == 100);

  /* equal: take pto (loss_time < pto_time is false) */
  CHECK(losstimer_next(100, 100, 1) == 100);

  /* armed only with ack-eliciting in flight */
  CHECK(losstimer_set(0) == 0);
  CHECK(losstimer_set(1) == 1);
  CHECK(losstimer_set(5) == 1);
}

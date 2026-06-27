#include "test.h"

/* RFC 9002 6.2 */
void test_losstimer(void)
{
    /* no loss time: always pto_time */
    CHECK(quic_losstimer_next(50, 100, 0) == 100);

    /* loss time earlier than pto: take loss time */
    CHECK(quic_losstimer_next(50, 100, 1) == 50);

    /* loss time later than pto: take pto */
    CHECK(quic_losstimer_next(150, 100, 1) == 100);

    /* equal: take pto (loss_time < pto_time is false) */
    CHECK(quic_losstimer_next(100, 100, 1) == 100);

    /* armed only with ack-eliciting in flight */
    CHECK(quic_losstimer_set(0) == 0);
    CHECK(quic_losstimer_set(1) == 1);
    CHECK(quic_losstimer_set(5) == 1);
}

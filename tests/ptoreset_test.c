#include "test.h"

/* RFC 9002 6.2.1 */
void test_ptoreset(void)
{
    /* ack received and nothing ack-eliciting still in flight: reset */
    CHECK(quic_pto_should_reset(1, 0) == 1);

    /* ack received but ack-eliciting still in flight: no reset */
    CHECK(quic_pto_should_reset(1, 3) == 0);

    /* no ack received: no reset regardless of in-flight */
    CHECK(quic_pto_should_reset(0, 0) == 0);
    CHECK(quic_pto_should_reset(0, 2) == 0);
}

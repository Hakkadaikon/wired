#include "test.h"

/* RFC 9000 13.2.1 / 13.2.2: ack a received ack-eliciting packet within
 * max_ack_delay; a second unacked one forces an immediate ack. */
void test_ackgen(void)
{
    /* non-eliciting packet, nothing pending: no ack */
    CHECK(quic_ackgen_should_ack(0, 0, 100, 25) == 0);

    /* first ack-eliciting packet: not due until max_ack_delay elapses */
    CHECK(quic_ackgen_should_ack(1, 0, 24, 25) == 0); /* 24 < 25 */
    CHECK(quic_ackgen_should_ack(1, 0, 25, 25) == 1); /* 25 >= 25 */

    /* second ack-eliciting packet while one is pending: immediate ack */
    CHECK(quic_ackgen_should_ack(1, 1, 0, 25) == 1);

    /* a pending ack-eliciting packet, no new packet: delay still governs */
    CHECK(quic_ackgen_should_ack(0, 1, 24, 25) == 0);
    CHECK(quic_ackgen_should_ack(0, 1, 25, 25) == 1);
}

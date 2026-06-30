#include "test.h"

/* RFC 9001 6.1/6.5: initiate only after handshake confirmed and at threshold. */
void test_kudrive_trigger(void)
{
    /* not confirmed -> never initiate, even past the threshold (6.1) */
    CHECK(quic_kudrive_should_initiate(100, 10, 0) == 0);
    CHECK(quic_kudrive_should_initiate(0, 0, 0) == 0);

    /* confirmed but below threshold */
    CHECK(quic_kudrive_should_initiate(9, 10, 1) == 0);

    /* confirmed, boundary: sent == threshold initiates */
    CHECK(quic_kudrive_should_initiate(10, 10, 1) == 1);

    /* confirmed, above threshold */
    CHECK(quic_kudrive_should_initiate(11, 10, 1) == 1);
}

#include "test.h"

/* RFC 9002 7.6: loss period >= kPersistentCongestionThreshold (3) PTOs. */
static void test_persistent_threshold(void)
{
    CHECK(quic_cc_persistent(299, 100) == 0);
    CHECK(quic_cc_persistent(300, 100) == 1); /* boundary: exactly 3*pto */
    CHECK(quic_cc_persistent(301, 100) == 1);
    CHECK(quic_cc_persistent(0, 0) == 1);     /* degenerate: 0 >= 0 */
}

/* RFC 9002 7.6: collapse to kMinimumWindow = 2 * max_datagram. */
static void test_persistent_cwnd(void)
{
    CHECK(quic_cc_persistent_cwnd(1200) == 2400);
}

void test_persistent(void)
{
    test_persistent_threshold();
    test_persistent_cwnd();
}

#include "test.h"

/* min_rtt keeps the smaller of itself and the new sample (RFC 9002 5.1). */
static void test_rttsample_min(void)
{
    CHECK(quic_rtt_min_update(100, 80) == 80);
    CHECK(quic_rtt_min_update(80, 100) == 80);
    CHECK(quic_rtt_min_update(80, 80) == 80);
}

/* ack_delay applies only above the min_rtt+ack_delay boundary (RFC 9002 5.3). */
static void test_rttsample_adjusted(void)
{
    /* below boundary: 90 < 50+50, keep latest unchanged */
    CHECK(quic_rtt_adjusted(90, 50, 50) == 90);
    /* exactly at boundary: 100 == 50+50, subtract */
    CHECK(quic_rtt_adjusted(100, 50, 50) == 50);
    /* above boundary: subtract */
    CHECK(quic_rtt_adjusted(120, 50, 50) == 70);
    /* zero ack_delay is a no-op */
    CHECK(quic_rtt_adjusted(120, 50, 0) == 120);
}

void test_rttsample(void)
{
    test_rttsample_min();
    test_rttsample_adjusted();
}

#include "test.h"

/* RFC 9002 7.7: interval = 5/4 * packet_size * srtt / cwnd. */
static void test_pacing_interval(void)
{
    /* 5*1200*8000 / (4*24000) = 48000000/96000 = 500 */
    CHECK(quic_pacing_interval(8000, 24000, 1200) == 500);
}

/* cwnd 0 returns 0 (avoid divide-by-zero, send now). */
static void test_pacing_zero_cwnd(void)
{
    CHECK(quic_pacing_interval(8000, 0, 1200) == 0);
}

/* srtt 0 yields 0 interval. */
static void test_pacing_zero_srtt(void)
{
    CHECK(quic_pacing_interval(0, 24000, 1200) == 0);
}

void test_pacing(void)
{
    test_pacing_interval();
    test_pacing_zero_cwnd();
    test_pacing_zero_srtt();
}

#include "test.h"

/* is_first is true exactly when no sample has been taken yet (RFC 9002 5.2). */
static void test_rttinit_is_first(void)
{
    CHECK(quic_rtt_is_first(0) == 1);
    CHECK(quic_rtt_is_first(1) == 0);
}

/* First sample: smoothed_rtt = latest, rttvar = latest/2 (RFC 9002 5.2). */
static void test_rttinit_seed(void)
{
    CHECK(quic_rtt_first_srtt(100000) == 100000);
    CHECK(quic_rtt_first_rttvar(100000) == 50000);
    CHECK(quic_rtt_first_rttvar(1) == 0); /* truncating divide */
}

void test_rttinit(void)
{
    test_rttinit_is_first();
    test_rttinit_seed();
}

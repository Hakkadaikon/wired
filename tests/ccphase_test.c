#include "test.h"

/* RFC 9002 7.3.1: below ssthresh is slow start; cwnd == ssthresh is not. */
static void test_ccphase_in_slow_start(void)
{
    CHECK(quic_cc_in_slow_start(100, 200) == 1);
    CHECK(quic_cc_in_slow_start(200, 200) == 0); /* boundary */
    CHECK(quic_cc_in_slow_start(201, 200) == 0);
}

/* RFC 9002 7.3.1: slow start grows by the bytes acked. */
static void test_ccphase_slow_start_inc(void)
{
    CHECK(quic_cc_slow_start_inc(0) == 0);
    CHECK(quic_cc_slow_start_inc(1200) == 1200);
}

/* RFC 9002 7.3.2: avoidance grows by max_datagram * acked / cwnd. */
static void test_ccphase_avoid_inc(void)
{
    CHECK(quic_cc_avoid_inc(1200, 1200, 12000) == 120);
    CHECK(quic_cc_avoid_inc(1200, 600, 1200) == 600);
    CHECK(quic_cc_avoid_inc(1200, 1, 1200) == 1);
    /* truncates toward zero when acked*max_datagram < cwnd */
    CHECK(quic_cc_avoid_inc(1200, 1, 2400) == 0);
}

void test_ccphase(void)
{
    test_ccphase_in_slow_start();
    test_ccphase_slow_start_inc();
    test_ccphase_avoid_inc();
}

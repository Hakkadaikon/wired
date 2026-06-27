#include "test.h"

/* First sample seeds smoothed_rtt and min_rtt to the sample (RFC 9002 5.2). */
static void test_rtt_first_sample(void)
{
    quic_rtt r;
    quic_rtt_init(&r);
    quic_rtt_sample(&r, 100000, 0);
    CHECK(r.smoothed_rtt == 100000 && r.min_rtt == 100000);
    CHECK(r.rttvar == 50000);
}

/* Constant samples keep smoothed_rtt pinned at that value (convex bound). */
static void test_rtt_constant_stays(void)
{
    quic_rtt r;
    quic_rtt_init(&r);
    quic_rtt_sample(&r, 80000, 0);
    for (usz i = 0; i < 20; i++) quic_rtt_sample(&r, 80000, 0);
    CHECK(r.smoothed_rtt == 80000); /* lo==hi: no integer-division drift */
}

/* Samples within [lo,hi] keep smoothed_rtt within [lo,hi] (prover R0-R3). */
static void test_rtt_within_bounds(void)
{
    quic_rtt r;
    quic_rtt_init(&r);
    u64 lo = 50000, hi = 150000;
    quic_rtt_sample(&r, lo, 0);
    u64 seq[] = {hi, lo, hi, hi, lo, 100000, hi, lo};
    for (usz i = 0; i < sizeof(seq) / sizeof(seq[0]); i++) {
        quic_rtt_sample(&r, seq[i], 0);
        CHECK(r.smoothed_rtt >= lo && r.smoothed_rtt <= hi);
    }
}

/* PTO = smoothed + max(4*rttvar, granularity) + max_ack_delay. */
static void test_rtt_pto(void)
{
    quic_rtt r;
    quic_rtt_init(&r);
    quic_rtt_sample(&r, 100000, 0); /* smoothed=100000, rttvar=50000 */
    CHECK(quic_rtt_pto(&r, 25000) == 100000 + 200000 + 25000);
}

void test_rtt(void)
{
    test_rtt_first_sample();
    test_rtt_constant_stays();
    test_rtt_within_bounds();
    test_rtt_pto();
}

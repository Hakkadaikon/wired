#include "test.h"

/* Backoff is 2^count and clamps at the max shift. */
static void test_pto_backoff(void)
{
    CHECK(quic_pto_backoff(0) == 1);
    CHECK(quic_pto_backoff(1) == 2);
    CHECK(quic_pto_backoff(4) == 16);
    CHECK(quic_pto_backoff(QUIC_PTO_BACKOFF_MAX) == ((u64)1 << QUIC_PTO_BACKOFF_MAX));
    CHECK(quic_pto_backoff(99) == ((u64)1 << QUIC_PTO_BACKOFF_MAX));
}

/* 4*rttvar dominates the granularity floor. */
static void test_pto_var_dominates(void)
{
    /* srtt=100000, rttvar=10000 -> 4*rttvar=40000 > 1000; +max_ack_delay=5000 */
    CHECK(quic_pto_duration(100000, 10000, 5000, 0) == 100000 + 40000 + 5000);
}

/* Granularity floor applies when 4*rttvar is tiny. */
static void test_pto_granularity_floor(void)
{
    /* 4*rttvar = 4 < 1000, so floor wins */
    CHECK(quic_pto_duration(100000, 1, 0, 0) == 100000 + QUIC_PTO_GRANULARITY);
}

/* Backoff multiplies the base PTO. */
static void test_pto_backoff_scales(void)
{
    u64 base = quic_pto_duration(100000, 10000, 5000, 0);
    CHECK(quic_pto_duration(100000, 10000, 5000, 3) == base * 8);
}

void test_pto(void)
{
    test_pto_backoff();
    test_pto_var_dominates();
    test_pto_granularity_floor();
    test_pto_backoff_scales();
}

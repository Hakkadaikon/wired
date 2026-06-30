#include "test.h"

/* Interval is half the idle timeout. */
static void test_keepalive_interval_half(void)
{
    CHECK(quic_keepalive_interval(30000) == 15000);
    CHECK(quic_keepalive_interval(1) == 0); /* integer division floor */
}

/* Due exactly at the half-timeout boundary, not just before it. */
static void test_keepalive_due_boundary(void)
{
    /* idle_timeout 30000 -> half 15000 */
    CHECK(!quic_keepalive_due(0, 14999, 30000)); /* just before half */
    CHECK(quic_keepalive_due(0, 15000, 30000));  /* exactly half */
    CHECK(quic_keepalive_due(0, 20000, 30000));  /* past half */
}

/* Boundary is measured from last activity, not absolute time. */
static void test_keepalive_due_from_last_activity(void)
{
    CHECK(!quic_keepalive_due(10000, 24999, 30000));
    CHECK(quic_keepalive_due(10000, 25000, 30000));
}

void test_keepalive(void)
{
    test_keepalive_interval_half();
    test_keepalive_due_boundary();
    test_keepalive_due_from_last_activity();
}

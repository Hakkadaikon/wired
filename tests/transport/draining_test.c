#include "test.h"

/* RFC 9000 10.2.2: the draining period is exactly 3*PTO. */
static void test_draining_period_is_3pto(void)
{
    CHECK(quic_draining_period(0) == 0);
    CHECK(quic_draining_period(1) == 3);
    CHECK(quic_draining_period(100) == 300);
}

/* Draining is done only at/after close_time + 3*PTO, not before. */
static void test_draining_done_boundary(void)
{
    /* close_time=1000, pto=100 -> period ends at 1300 */
    CHECK(quic_draining_done(1000, 1299, 100) == 0); /* one tick early */
    CHECK(quic_draining_done(1000, 1300, 100) == 1); /* exactly at limit */
    CHECK(quic_draining_done(1000, 1301, 100) == 1); /* past limit */
    CHECK(quic_draining_done(1000, 1000, 100) == 0); /* just entered */
}

/* Sending is forbidden during draining, allowed otherwise. */
static void test_draining_may_send(void)
{
    CHECK(quic_draining_may_send(1) == 0); /* in draining: cannot send */
    CHECK(quic_draining_may_send(0) == 1); /* not draining: may send */
}

void test_draining(void)
{
    test_draining_period_is_3pto();
    test_draining_done_boundary();
    test_draining_may_send();
}

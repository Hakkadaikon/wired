#include "test.h"

/* Budget is 3x received minus sent, clamped at zero. */
static void test_antiamp_budget(void)
{
    CHECK(quic_antiamp_budget(100, 0) == 300);
    CHECK(quic_antiamp_budget(100, 250) == 50);
    CHECK(quic_antiamp_budget(100, 300) == 0); /* exactly at the limit */
    CHECK(quic_antiamp_budget(100, 301) == 0); /* over: clamped, no wrap */
    CHECK(quic_antiamp_budget(0, 0) == 0);
}

/* can_send tracks the budget at the 3x boundary. */
static void test_antiamp_can_send(void)
{
    CHECK(quic_antiamp_can_send(100, 0, 300) == 1); /* exactly 3x */
    CHECK(quic_antiamp_can_send(100, 0, 301) == 0); /* 3x + 1 refused */
    CHECK(quic_antiamp_can_send(100, 250, 50) == 1);
    CHECK(quic_antiamp_can_send(100, 250, 51) == 0);
    CHECK(quic_antiamp_can_send(0, 0, 1) == 0); /* nothing received yet */
}

void test_antiamp(void)
{
    test_antiamp_budget();
    test_antiamp_can_send();
}

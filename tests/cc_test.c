#include "test.h"

static void test_cc_slow_start(void)
{
    quic_cc c;
    quic_cc_init(&c);
    u64 start = c.cwnd;
    quic_cc_on_ack(&c, 1200, 10);     /* slow start: +acked */
    CHECK(c.cwnd == start + 1200);
}

/* Loss halves cwnd but never below the minimum window (most important). */
static void test_cc_loss_halves_floor(void)
{
    quic_cc c;
    quic_cc_init(&c);
    quic_cc_on_loss(&c, 5, 100);
    CHECK(c.cwnd == QUIC_CC_INIT_WINDOW / 2);
    CHECK(c.cwnd >= QUIC_CC_MIN_WINDOW);
    /* drive it down repeatedly: must clamp at the floor */
    for (usz i = 0; i < 20; i++) {
        quic_cc_on_ack(&c, 999999, 1000 + i); /* exit recovery */
        quic_cc_on_loss(&c, 2000 + i, 2000 + i);
    }
    CHECK(c.cwnd >= QUIC_CC_MIN_WINDOW);
}

/* No window growth while in recovery. */
static void test_cc_no_grow_in_recovery(void)
{
    quic_cc c;
    quic_cc_init(&c);
    quic_cc_on_loss(&c, 5, 100);          /* enter recovery at t=100 */
    u64 w = c.cwnd;
    quic_cc_on_ack(&c, 1200, 50);         /* ack of pre-recovery packet */
    CHECK(c.in_recovery == 1 && c.cwnd == w);
}

/* An ack of a packet sent after recovery began exits recovery. */
static void test_cc_recovery_exit(void)
{
    quic_cc c;
    quic_cc_init(&c);
    quic_cc_on_loss(&c, 5, 100);
    quic_cc_on_ack(&c, 1200, 200);        /* sent after recovery_start=100 */
    CHECK(c.in_recovery == 0);
}

static void test_cc_persistent_collapse(void)
{
    quic_cc c;
    quic_cc_init(&c);
    quic_cc_on_persistent(&c);
    CHECK(c.cwnd == QUIC_CC_MIN_WINDOW);
}

void test_cc(void)
{
    test_cc_slow_start();
    test_cc_loss_halves_floor();
    test_cc_no_grow_in_recovery();
    test_cc_recovery_exit();
    test_cc_persistent_collapse();
}

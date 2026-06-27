#include "test.h"

/* A fresh state permits no pushes. */
static void test_push_init(void)
{
    quic_h3_push_state s;
    quic_h3_push_init(&s);
    CHECK(quic_h3_push_allowed(&s, 0) == 0);
}

/* Raising the maximum permits IDs strictly below it. */
static void test_push_set_max(void)
{
    quic_h3_push_state s;
    quic_h3_push_init(&s);
    CHECK(quic_h3_push_set_max(&s, 3) == 1);
    CHECK(quic_h3_push_allowed(&s, 0) == 1);
    CHECK(quic_h3_push_allowed(&s, 2) == 1);
    CHECK(quic_h3_push_allowed(&s, 3) == 0);  /* id == max is not allowed */
}

/* The maximum may be raised again but never lowered. */
static void test_push_monotonic(void)
{
    quic_h3_push_state s;
    quic_h3_push_init(&s);
    CHECK(quic_h3_push_set_max(&s, 5) == 1);
    CHECK(quic_h3_push_set_max(&s, 5) == 1);  /* equal holds */
    CHECK(quic_h3_push_set_max(&s, 10) == 1); /* raise */
    CHECK(quic_h3_push_set_max(&s, 9) == 0);  /* lower rejected */
    CHECK(quic_h3_push_allowed(&s, 9) == 1);  /* max unchanged at 10 */
}

void test_pushid(void)
{
    test_push_init();
    test_push_set_max();
    test_push_monotonic();
}

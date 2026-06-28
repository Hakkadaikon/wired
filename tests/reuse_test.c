#include "test.h"

/* Reuse requires all three conditions; any single failure forbids it. */
static void test_reuse_all_conditions(void)
{
    CHECK(quic_h3_conn_reusable(1, 1, 1));
    CHECK(!quic_h3_conn_reusable(0, 1, 1)); /* different origin */
    CHECK(!quic_h3_conn_reusable(1, 0, 1)); /* connection dead */
    CHECK(!quic_h3_conn_reusable(1, 1, 0)); /* incompatible version */
    CHECK(!quic_h3_conn_reusable(0, 0, 0));
}

void test_reuse(void)
{
    test_reuse_all_conditions();
}

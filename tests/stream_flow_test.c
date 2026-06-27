#include "test.h"
#include "flow/stream_flow.c"

static void test_stream_flow_consume(void)
{
    quic_stream_flow s;
    quic_stream_flow_init(&s, 1000);
    CHECK(s.max_stream_data == 1000);
    CHECK(quic_stream_flow_consume(&s, 400) == 1400); /* limit slides forward */
    CHECK(quic_stream_flow_consume(&s, 100) == 1500);
}

static void test_stream_flow_violation(void)
{
    CHECK(quic_stream_flow_violation(1000, 1000) == 0); /* exactly at limit */
    CHECK(quic_stream_flow_violation(999, 1000) == 0);
    CHECK(quic_stream_flow_violation(1001, 1000) == 1); /* over the limit */
}

void test_stream_flow(void)
{
    test_stream_flow_consume();
    test_stream_flow_violation();
}

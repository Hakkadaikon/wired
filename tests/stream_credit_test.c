#include "test.h"

static void test_stream_credit_open_up_to_limit(void)
{
    quic_stream_credit s;
    quic_stream_credit_init(&s, 2);
    CHECK(quic_stream_credit_open(&s) == 1);
    CHECK(quic_stream_credit_open(&s) == 1);
    CHECK(quic_stream_credit_open(&s) == 0); /* limit reached */
    CHECK(s.count == 2);                     /* rejected open did not count */
}

static void test_stream_credit_grant_raises(void)
{
    quic_stream_credit s;
    quic_stream_credit_init(&s, 1);
    CHECK(quic_stream_credit_open(&s) == 1);
    CHECK(quic_stream_credit_open(&s) == 0);

    quic_stream_credit_grant(&s, 3); /* MAX_STREAMS raises the ceiling */
    CHECK(quic_stream_credit_open(&s) == 1);
    CHECK(quic_stream_credit_open(&s) == 1);
    CHECK(quic_stream_credit_open(&s) == 0);
}

static void test_stream_credit_grant_never_lowers(void)
{
    quic_stream_credit s;
    quic_stream_credit_init(&s, 5);
    quic_stream_credit_grant(&s, 2); /* smaller grant ignored */
    CHECK(s.max_streams == 5);
}

void test_stream_credit(void)
{
    test_stream_credit_open_up_to_limit();
    test_stream_credit_grant_raises();
    test_stream_credit_grant_never_lowers();
}

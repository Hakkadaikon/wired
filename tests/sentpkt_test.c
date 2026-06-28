#include "test.h"

static void test_sentpkt_init_empty(void)
{
    quic_sentpkt t;
    quic_sentpkt_init(&t);
    CHECK(quic_sentpkt_count(&t) == 0);
}

static void test_sentpkt_count_after_send(void)
{
    quic_sentpkt t;
    quic_sentpkt_init(&t);
    CHECK(quic_sentpkt_on_send(&t, 1, 100, 1, 1200) == 1);
    CHECK(quic_sentpkt_on_send(&t, 2, 200, 0, 40) == 1);
    CHECK(quic_sentpkt_count(&t) == 2);
}

/* Capacity boundary: the (CAP+1)th send is rejected and not counted. */
static void test_sentpkt_full(void)
{
    quic_sentpkt t;
    quic_sentpkt_init(&t);
    for (u64 pn = 0; pn < QUIC_SENTPKT_CAP; pn++)
        CHECK(quic_sentpkt_on_send(&t, pn, 0, 1, 1) == 1);
    CHECK(quic_sentpkt_on_send(&t, QUIC_SENTPKT_CAP, 0, 1, 1) == 0);
    CHECK(quic_sentpkt_count(&t) == QUIC_SENTPKT_CAP);
}

void test_sentpkt(void)
{
    test_sentpkt_init_empty();
    test_sentpkt_count_after_send();
    test_sentpkt_full();
}

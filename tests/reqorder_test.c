#include "test.h"

/* RFC 9114 4.1: a request stream begins with HEADERS, not DATA. */
static void test_reqorder_leading(void)
{
    quic_h3req_order_state s;
    quic_h3req_order_init(&s);
    CHECK(s == QUIC_H3REQ_ORDER_START);

    quic_h3req_order_init(&s);
    CHECK(quic_h3req_order_accept(&s, QUIC_H3_FRAME_HEADERS) == 1);
    CHECK(s == QUIC_H3REQ_ORDER_HEADERS);

    quic_h3req_order_init(&s);
    CHECK(quic_h3req_order_accept(&s, QUIC_H3_FRAME_DATA) == 0);
    CHECK(s == QUIC_H3REQ_ORDER_START);
}

/* HEADERS -> DATA -> trailing HEADERS is the full allowed sequence. */
static void test_reqorder_full(void)
{
    quic_h3req_order_state s;
    quic_h3req_order_init(&s);
    CHECK(quic_h3req_order_accept(&s, QUIC_H3_FRAME_HEADERS) == 1);
    CHECK(quic_h3req_order_accept(&s, QUIC_H3_FRAME_DATA) == 1);
    CHECK(quic_h3req_order_accept(&s, QUIC_H3_FRAME_DATA) == 1);
    CHECK(quic_h3req_order_accept(&s, QUIC_H3_FRAME_HEADERS) == 1);
    CHECK(s == QUIC_H3REQ_ORDER_TRAILERS);
}

/* Nothing is allowed after the trailer; a third HEADERS is rejected. */
static void test_reqorder_after_trailer(void)
{
    quic_h3req_order_state s;
    quic_h3req_order_init(&s);
    quic_h3req_order_accept(&s, QUIC_H3_FRAME_HEADERS);
    quic_h3req_order_accept(&s, QUIC_H3_FRAME_HEADERS);
    CHECK(quic_h3req_order_accept(&s, QUIC_H3_FRAME_DATA) == 0);
    CHECK(quic_h3req_order_accept(&s, QUIC_H3_FRAME_HEADERS) == 0);
    CHECK(s == QUIC_H3REQ_ORDER_TRAILERS);
}

void test_reqorder(void)
{
    test_reqorder_leading();
    test_reqorder_full();
    test_reqorder_after_trailer();
}

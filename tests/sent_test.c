#include "test.h"

static void test_sent_ack_accounting(void)
{
    quic_sent s;
    quic_sent_init(&s);
    quic_sent_on_send(&s, 1, 100, 0);
    quic_sent_on_send(&s, 2, 200, 0);
    CHECK(s.bytes_in_flight == 300);
    CHECK(quic_sent_on_ack(&s, 1) == 1);
    CHECK(s.bytes_in_flight == 200);
    /* duplicate ack is idempotent: no double decrement */
    CHECK(quic_sent_on_ack(&s, 1) == 0);
    CHECK(s.bytes_in_flight == 200);
}

static void test_sent_largest_acked_monotonic(void)
{
    quic_sent s;
    quic_sent_init(&s);
    for (u64 pn = 1; pn <= 5; pn++) quic_sent_on_send(&s, pn, 10, 0);
    quic_sent_on_ack(&s, 5);
    CHECK(s.largest_acked == 5);
    quic_sent_on_ack(&s, 2);            /* older ack must not lower it */
    CHECK(s.largest_acked == 5);
}

/* Packet threshold = 3: a packet exactly 3 below largest_acked is lost,
 * one only 2 below is not (modeler: the >= boundary, off-by-one is a bug). */
static void test_sent_packet_threshold_3(void)
{
    quic_sent s;
    quic_sent_init(&s);
    quic_sent_on_send(&s, 1, 10, 0); /* 4 below 5 -> lost */
    quic_sent_on_send(&s, 2, 10, 0); /* 3 below 5 -> lost (boundary) */
    quic_sent_on_send(&s, 3, 10, 0); /* 2 below 5 -> NOT lost */
    quic_sent_on_send(&s, 5, 10, 0);
    quic_sent_on_ack(&s, 5);
    CHECK(quic_sent_detect_loss(&s) == 2);
    CHECK(s.pkts[0].state == QUIC_PKT_LOST);
    CHECK(s.pkts[1].state == QUIC_PKT_LOST);
    CHECK(s.pkts[2].state == QUIC_PKT_INFLIGHT);
}

/* An acked packet is never later marked lost (acked/lost exclusivity). */
static void test_sent_acked_never_lost(void)
{
    quic_sent s;
    quic_sent_init(&s);
    quic_sent_on_send(&s, 1, 10, 0);
    quic_sent_on_send(&s, 5, 10, 0);
    quic_sent_on_ack(&s, 1);             /* pn 1 acked */
    quic_sent_on_ack(&s, 5);
    quic_sent_detect_loss(&s);
    CHECK(s.pkts[0].state == QUIC_PKT_ACKED); /* stays acked, not lost */
    /* bytes_in_flight: pn1 acked, pn5 acked -> 0 */
    CHECK(s.bytes_in_flight == 0);
}

void test_sent(void)
{
    test_sent_ack_accounting();
    test_sent_largest_acked_monotonic();
    test_sent_packet_threshold_3();
    test_sent_acked_never_lost();
}

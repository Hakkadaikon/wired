#include "test.h"

/* RFC 9002 2: ack-eliciting iff a non-ACK/PADDING/CC frame is present. */
static void test_inflight_ack_eliciting(void)
{
    CHECK(quic_pkt_ack_eliciting(0) == 0);
    CHECK(quic_pkt_ack_eliciting(1) == 1);
}

/* RFC 9002 2: in-flight iff ack-eliciting or PADDING-bearing. */
static void test_inflight_in_flight(void)
{
    CHECK(quic_pkt_in_flight(0, 0) == 0);
    CHECK(quic_pkt_in_flight(1, 0) == 1);
    CHECK(quic_pkt_in_flight(0, 1) == 1);
    CHECK(quic_pkt_in_flight(1, 1) == 1);
}

/* RFC 9002 A.5: only in-flight packets count bytes toward congestion control. */
static void test_inflight_counts_bytes(void)
{
    CHECK(quic_pkt_counts_bytes(0, 1200) == 0);
    CHECK(quic_pkt_counts_bytes(1, 1200) == 1200);
    CHECK(quic_pkt_counts_bytes(1, 0) == 0);
}

void test_inflight(void)
{
    test_inflight_ack_eliciting();
    test_inflight_in_flight();
    test_inflight_counts_bytes();
}

#include "test.h"

/* RFC 9002 5.1: RTT sample requires newly-acked largest AND ack-eliciting. */
static void test_rttvalid_sample_valid(void)
{
    CHECK(quic_rtt_sample_valid(1, 1) == 1);
    CHECK(quic_rtt_sample_valid(1, 0) == 0);
    CHECK(quic_rtt_sample_valid(0, 1) == 0);
    CHECK(quic_rtt_sample_valid(0, 0) == 0);
}

/* RFC 9002 5.1: latest_rtt = now - sent_time, clamped at 0 on underflow. */
static void test_rttvalid_sample_time(void)
{
    CHECK(quic_rtt_sample_time(1000, 400) == 600);
    CHECK(quic_rtt_sample_time(400, 400) == 0); /* boundary: equal -> 0 */
    CHECK(quic_rtt_sample_time(300, 400) == 0); /* underflow clamps to 0 */
}

void test_rttvalid(void)
{
    test_rttvalid_sample_valid();
    test_rttvalid_sample_time();
}

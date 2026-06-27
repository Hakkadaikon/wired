#include "test.h"

/* Packet threshold: lost exactly when largest_acked - pn >= 3. */
static void test_loss_by_packet_boundary(void)
{
    CHECK(quic_loss_by_packet(10, 7) == 1);  /* gap 3 */
    CHECK(quic_loss_by_packet(10, 8) == 0);  /* gap 2 */
    CHECK(quic_loss_by_packet(10, 10) == 0); /* same packet */
    CHECK(quic_loss_by_packet(3, 0) == 1);   /* gap 3 from zero */
}

/* Time threshold: lost when elapsed >= 9/8 * max(srtt, latest). */
static void test_loss_by_time_boundary(void)
{
    /* srtt=8000, latest=8000 -> threshold = 8000*9/8 = 9000 */
    CHECK(quic_loss_by_time(9000, 0, 8000, 8000) == 1); /* exactly at threshold */
    CHECK(quic_loss_by_time(8999, 0, 8000, 8000) == 0); /* just under */
}

/* Uses the larger of srtt and latest_rtt. */
static void test_loss_by_time_uses_max(void)
{
    /* max(4000, 8000)=8000 -> threshold 9000 */
    CHECK(quic_loss_by_time(9000, 0, 4000, 8000) == 1);
    CHECK(quic_loss_by_time(9000, 0, 8000, 4000) == 1);
}

/* now before sent_time: elapsed is zero, not lost (threshold > 0). */
static void test_loss_by_time_no_underflow(void)
{
    CHECK(quic_loss_by_time(100, 5000, 8000, 8000) == 0);
}

void test_lossdetect(void)
{
    test_loss_by_packet_boundary();
    test_loss_by_time_boundary();
    test_loss_by_time_uses_max();
    test_loss_by_time_no_underflow();
}

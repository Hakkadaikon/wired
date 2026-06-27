#include "test.h"

/* RFC 9002 7.3.2: ssthresh = cwnd * kLossReductionFactor (0.5). */
static void test_ccloss_ssthresh(void)
{
    CHECK(quic_cc_on_loss_ssthresh(12000) == 6000);
    CHECK(quic_cc_on_loss_ssthresh(1) == 0);
}

/* RFC 9002 7.3.2: cwnd = max(cwnd/2, kMinimumWindow = 2*max_datagram). */
static void test_ccloss_cwnd_floor(void)
{
    /* halving wins */
    CHECK(quic_cc_on_loss_cwnd(12000, 1200) == 6000);
    /* floor wins: 2*1200 = 2400, half of 2400 = 1200 < 2400 */
    CHECK(quic_cc_on_loss_cwnd(2400, 1200) == 2400);
    /* boundary: half equals floor exactly */
    CHECK(quic_cc_on_loss_cwnd(4800, 1200) == 2400);
}

/* RFC 9002 7.3.2: sent at or before recovery_start is in recovery. */
static void test_ccloss_in_recovery(void)
{
    CHECK(quic_cc_in_recovery(50, 100) == 1);
    CHECK(quic_cc_in_recovery(100, 100) == 1); /* boundary */
    CHECK(quic_cc_in_recovery(101, 100) == 0);
}

void test_ccloss(void)
{
    test_ccloss_ssthresh();
    test_ccloss_cwnd_floor();
    test_ccloss_in_recovery();
}

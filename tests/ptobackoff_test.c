#include "test.h"

/* count=0: plain PTO, no scaling. */
static void test_pto_no_backoff(void)
{
    /* srtt=10000 + max(4*1000,1000)=4000 + ack_delay=2000 = 16000 */
    CHECK(quic_lossdrive_pto(10000, 1000, 2000, 0, 1000) == 16000);
}

/* count=2: PTO scaled by 2^2 = 4. */
static void test_pto_backoff_four(void)
{
    CHECK(quic_lossdrive_pto(10000, 1000, 2000, 2, 1000) == 64000);
}

/* rttvar small: granularity is the lower bound on the variance term. */
static void ptobackoff_granularity_floor(void)
{
    /* max(4*0,1000)=1000 -> 5000+1000+0 = 6000 */
    CHECK(quic_lossdrive_pto(5000, 0, 0, 0, 1000) == 6000);
}

void test_ptobackoff(void)
{
    test_pto_no_backoff();
    test_pto_backoff_four();
    ptobackoff_granularity_floor();
}

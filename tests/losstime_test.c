#include "test.h"

/* RFC 9002 6.1.2: time-threshold loss detection. */
void test_losstime(void)
{
    /* 9/8 of max(srtt, latest_rtt) when it exceeds granularity */
    CHECK(quic_losstime_threshold(8000, 4000, 1000) == 9000);
    CHECK(quic_losstime_threshold(4000, 8000, 1000) == 9000);
    /* granularity floor wins when 9/8 * rtt is smaller */
    CHECK(quic_losstime_threshold(100, 100, 1000) == 1000);

    /* time_sent + loss_delay <= now -> lost */
    CHECK(quic_losstime_is_lost(1000, 2000, 1000) == 1);
    CHECK(quic_losstime_is_lost(1000, 2500, 1000) == 1);
    /* not yet past the threshold -> not lost */
    CHECK(quic_losstime_is_lost(1000, 1999, 1000) == 0);
}

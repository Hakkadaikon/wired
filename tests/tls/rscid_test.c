#include "test.h"

void test_rscid(void)
{
    u8 rscid[6] = {1, 1, 2, 3, 5, 8};
    u8 same[6] = {1, 1, 2, 3, 5, 8};
    u8 diff[6] = {1, 1, 2, 3, 5, 9};

    /* Retry occurred, parameter present and matching -> ok */
    CHECK(quic_tpverify_rscid(1, rscid, 6, same, 6, 1) == 1);
    /* Retry occurred, parameter present but mismatching -> violation */
    CHECK(quic_tpverify_rscid(1, rscid, 6, diff, 6, 1) == 0);
    /* Retry occurred but parameter absent -> violation */
    CHECK(quic_tpverify_rscid(1, rscid, 6, 0, 0, 0) == 0);
    /* No Retry and parameter present -> violation */
    CHECK(quic_tpverify_rscid(0, 0, 0, same, 6, 1) == 0);
    /* No Retry and parameter absent -> ok */
    CHECK(quic_tpverify_rscid(0, 0, 0, 0, 0, 0) == 1);
}

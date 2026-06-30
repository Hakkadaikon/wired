#include "test.h"

void test_odcid(void)
{
    u8 dcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    u8 same[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    u8 diff[8] = {1, 2, 3, 4, 5, 6, 7, 9};
    u8 shortc[4] = {1, 2, 3, 4};

    CHECK(quic_tpverify_odcid(dcid, 8, same, 8) == 1);
    CHECK(quic_tpverify_odcid(dcid, 8, diff, 8) == 0);
    CHECK(quic_tpverify_odcid(dcid, 8, shortc, 4) == 0); /* length mismatch */
    CHECK(quic_tpverify_odcid(dcid, 0, same, 0) == 1);   /* zero-length CIDs */
}

#include "test.h"

void test_iscid(void)
{
    u8 scid[5] = {10, 20, 30, 40, 50};
    u8 same[5] = {10, 20, 30, 40, 50};
    u8 diff[5] = {10, 20, 30, 40, 51};

    CHECK(quic_tpverify_iscid(scid, 5, same, 5) == 1);
    CHECK(quic_tpverify_iscid(scid, 5, diff, 5) == 0);
    CHECK(quic_tpverify_iscid(scid, 5, same, 4) == 0); /* length mismatch */
}

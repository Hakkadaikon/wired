#include "test.h"

/* RFC 9001 5.4.2: sample starts at pn_offset + 4. */
static void test_hpsample_offset(void)
{
    CHECK(quic_hp_sample_offset(0) == 4);
    CHECK(quic_hp_sample_offset(17) == 21);
}

/* sample_offset + 16 must fit within packet_len. */
static void test_hpsample_ok(void)
{
    CHECK(quic_hp_sample_ok(20, 4) == 1);   /* 4+16 == 20, exact fit */
    CHECK(quic_hp_sample_ok(19, 4) == 0);   /* one short */
    CHECK(quic_hp_sample_ok(100, 21) == 1);
    CHECK(quic_hp_sample_ok(36, 21) == 0);  /* 21+16 == 37 > 36 */
}

void test_hpsample(void)
{
    test_hpsample_offset();
    test_hpsample_ok();
}

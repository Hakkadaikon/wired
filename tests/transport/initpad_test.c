#include "test.h"

/* RFC 9000 14.1: short Initial datagrams pad to 1200; larger ones stay. */
void test_initpad(void)
{
    u8 buf[1300];
    for (usz i = 0; i < sizeof(buf); i++) buf[i] = 0xFF;

    /* under 1200 -> padded to 1200 with 0x00 */
    CHECK(quic_pktbuild_init_pad(buf, 100, sizeof(buf)) == 1200);
    for (usz i = 100; i < 1200; i++) CHECK(buf[i] == 0x00);
    CHECK(buf[99] == 0xFF);   /* existing bytes untouched */

    /* exactly 1200 -> unchanged */
    CHECK(quic_pktbuild_init_pad(buf, 1200, sizeof(buf)) == 1200);
    /* over 1200 -> unchanged */
    CHECK(quic_pktbuild_init_pad(buf, 1250, sizeof(buf)) == 1250);

    /* cap too small to reach 1200 -> unchanged */
    u8 small[500];
    CHECK(quic_pktbuild_init_pad(small, 100, sizeof(small)) == 100);
}

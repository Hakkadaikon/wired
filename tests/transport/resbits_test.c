#include "test.h"

/* Reserved bits zero is valid; any set reserved bit is a violation. */
static void test_resbits(void)
{
    /* long header: reserved bits 0x0c must be zero */
    CHECK(quic_resbits_ok(0xC3, 1) == 1); /* 0xC3 has no 0x0c bits set */
    CHECK(quic_resbits_ok(0xC4, 1) == 0); /* 0x04 is a reserved bit */
    CHECK(quic_resbits_ok(0xC8, 1) == 0); /* 0x08 is a reserved bit */

    /* short header: reserved bits 0x18 must be zero */
    CHECK(quic_resbits_ok(0x40, 0) == 1); /* fixed bit only, reserved clear */
    CHECK(quic_resbits_ok(0x48, 0) == 0); /* 0x08 is a reserved bit */
    CHECK(quic_resbits_ok(0x50, 0) == 0); /* 0x10 is a reserved bit */
}

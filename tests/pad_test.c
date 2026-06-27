#include "test.h"
#include "packet/pad.c"

/* Padding brings a short datagram up to 1200 bytes; larger ones need none. */
static void test_pad(void)
{
    CHECK(quic_pad_needed(0) == 1200);
    CHECK(quic_pad_needed(200) == 1000);
    CHECK(quic_pad_needed(1199) == 1);
    CHECK(quic_pad_needed(1200) == 0);   /* exactly the minimum */
    CHECK(quic_pad_needed(1500) == 0);   /* already large enough */
}

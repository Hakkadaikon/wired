#include "test.h"

/* With the default exponent 3, the field value scales by 8. */
static void test_ackdelay(void)
{
    /* 1000 us / 8 = 125 (floor); 125 * 8 = 1000 back */
    CHECK(quic_ack_delay_encode(1000, 3) == 125);
    CHECK(quic_ack_delay_decode(125, 3) == 1000);

    /* a non-default exponent */
    CHECK(quic_ack_delay_encode(4096, 10) == 4);
    CHECK(quic_ack_delay_decode(4, 10) == 4096);

    /* low bits below the exponent are truncated, as the field is coarse */
    CHECK(quic_ack_delay_encode(1007, 3) == 125); /* 1007>>3 = 125 */
    CHECK(quic_ack_delay_decode(quic_ack_delay_encode(1007, 3), 3) == 1000);
}

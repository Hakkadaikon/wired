#include "test.h"

/* RFC 9001 6.2: the Key Phase bit reflects the generation's low bit. */
void test_kuswitch_phasebit(void)
{
    CHECK(quic_kuswitch_phase_bit(0) == 0);
    CHECK(quic_kuswitch_phase_bit(1) == 1);
    CHECK(quic_kuswitch_phase_bit(2) == 0);
    CHECK(quic_kuswitch_phase_bit(3) == 1);

    /* apply_phase sets 0x04 per generation, leaving other bits intact */
    u8 b = 0x41; /* short header form bits, phase clear */
    quic_kuswitch_apply_phase(&b, 0);
    CHECK(b == 0x41); /* gen 0 -> bit 0 */
    quic_kuswitch_apply_phase(&b, 1);
    CHECK(b == 0x45); /* gen 1 -> bit 1 (0x04 set) */
    quic_kuswitch_apply_phase(&b, 2);
    CHECK(b == 0x41); /* gen 2 -> bit 0 again, 0x41 untouched */
}

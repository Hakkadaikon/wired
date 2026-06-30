#include "test.h"

/* RFC 9001 6: Key Phase bit (0x04) tracks the generation's low bit. */
void test_keyphase(void)
{
    /* bit follows generation parity */
    CHECK(quic_keyphase_bit(0) == 0);
    CHECK(quic_keyphase_bit(1) == 1);
    CHECK(quic_keyphase_bit(2) == 0);
    CHECK(quic_keyphase_bit(3) == 1);

    /* get reads bit 0x04, ignoring other bits */
    CHECK(quic_keyphase_get(0x00) == 0);
    CHECK(quic_keyphase_get(0x04) == 1);
    CHECK(quic_keyphase_get(0xFB) == 0); /* every bit but 0x04 set */
    CHECK(quic_keyphase_get(0xFF) == 1);

    /* set toggles only 0x04, leaving the rest intact */
    CHECK(quic_keyphase_set(0x41, 1) == 0x45);
    CHECK(quic_keyphase_set(0x45, 0) == 0x41);
    CHECK(quic_keyphase_set(0x45, 1) == 0x45); /* idempotent when already set */

    /* round-trip: set then get recovers the phase */
    CHECK(quic_keyphase_get(quic_keyphase_set(0x40, 1)) == 1);
    CHECK(quic_keyphase_get(quic_keyphase_set(0x40, 0)) == 0);
}

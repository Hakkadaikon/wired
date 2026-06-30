#include "test.h"

/* RFC 9001 6.5: old keys discardable, and re-update allowed, after 3*PTO. */
void test_kudrive_discard_timing(void)
{
    u64 completed = 1000, pto = 50; /* 3*PTO = 150, mark+3PTO = 1150 */

    /* boundary: now = completed + 3*PTO - 1 -> not yet */
    CHECK(quic_kudrive_can_discard_old(1149, completed, pto) == 0);
    /* boundary: now = completed + 3*PTO -> discardable */
    CHECK(quic_kudrive_can_discard_old(1150, completed, pto) == 1);
    CHECK(quic_kudrive_can_discard_old(2000, completed, pto) == 1);

    /* re-initiate: within 3*PTO of last update is rejected (DoS floor) */
    u64 last = 500; /* last+3PTO = 650 */
    CHECK(quic_kudrive_can_initiate_again(649, last, pto) == 0);
    CHECK(quic_kudrive_can_initiate_again(650, last, pto) == 1);
}

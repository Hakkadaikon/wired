#include "test.h"
#include "keyupdate/oldkey.c"

/* RFC 9001 6.1/6.5: retain the old key for 3*PTO, then discard. */
void test_oldkey(void)
{
    u64 t = 1000, pto = 100; /* 3*PTO window = 300, ends at t+300 = 1300 */

    /* well inside the window: retained, not discardable */
    CHECK(quic_oldkey_retain(t, 1100, pto));
    CHECK(!quic_oldkey_can_discard(t, 1100, pto));

    /* just before the boundary: still retained */
    CHECK(quic_oldkey_retain(t, 1299, pto));

    /* exactly at 3*PTO: window closed, may discard */
    CHECK(!quic_oldkey_retain(t, 1300, pto));
    CHECK(quic_oldkey_can_discard(t, 1300, pto));

    /* past the boundary: discardable */
    CHECK(quic_oldkey_can_discard(t, 1301, pto));

    /* at the update instant: fully retained */
    CHECK(quic_oldkey_retain(t, t, pto));
}

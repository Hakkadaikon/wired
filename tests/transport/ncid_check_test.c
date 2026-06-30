#include "test.h"

void test_ncid_check(void)
{
    /* retire_prior_to vs seq */
    CHECK(quic_ncid_check(5, 0, 8) == 1);
    CHECK(quic_ncid_check(5, 5, 8) == 1);   /* equal is allowed */
    CHECK(quic_ncid_check(5, 6, 8) == 0);   /* greater is rejected */
    CHECK(quic_ncid_check(0, 0, 8) == 1);

    /* cid_len boundaries 1..20 */
    CHECK(quic_ncid_check(1, 0, 0) == 0);   /* zero length rejected */
    CHECK(quic_ncid_check(1, 0, 1) == 1);   /* min */
    CHECK(quic_ncid_check(1, 0, 20) == 1);  /* max */
    CHECK(quic_ncid_check(1, 0, 21) == 0);  /* over max */
    CHECK(quic_ncid_check(1, 0, 255) == 0);
}

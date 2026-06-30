#include "test.h"

/* Both endpoints advertise a limit: the smaller one wins. */
static void test_idlenego_both_nonzero_min(void)
{
    CHECK(quic_idledrive_effective(30, 50) == 30);
    CHECK(quic_idledrive_effective(50, 30) == 30);
}

/* One endpoint advertises 0 (no limit): the other one applies. */
static void test_idlenego_one_zero(void)
{
    CHECK(quic_idledrive_effective(0, 40) == 40);
    CHECK(quic_idledrive_effective(40, 0) == 40);
}

/* Neither advertises a limit: no idle timeout. */
static void test_idlenego_both_zero(void)
{
    CHECK(quic_idledrive_effective(0, 0) == 0);
}

void test_idlenego(void)
{
    test_idlenego_both_nonzero_min();
    test_idlenego_one_zero();
    test_idlenego_both_zero();
}

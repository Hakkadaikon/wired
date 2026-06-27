#include "test.h"
#include "qpack/relindex.h"

/* RFC 9204 3.2.5: relative index 0 is the entry just below Base, and the
 * absolute index decreases as the relative index grows. */
static void test_qpack_rel_to_abs(void)
{
    CHECK(quic_qpack_rel_to_abs(6, 0) == 5);
    CHECK(quic_qpack_rel_to_abs(6, 5) == 0);
}

/* RFC 9204 3.2.6: post-base index 0 is the entry at Base, growing upward. */
static void test_qpack_postbase_to_abs(void)
{
    CHECK(quic_qpack_postbase_to_abs(6, 0) == 6);
    CHECK(quic_qpack_postbase_to_abs(6, 3) == 9);
}

void test_relindex(void)
{
    test_qpack_rel_to_abs();
    test_qpack_postbase_to_abs();
}

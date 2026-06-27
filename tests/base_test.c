#include "test.h"
#include "qpack/base.h"

/* RFC 9204 4.5.1.2: with Sign 0 the Base is RIC plus Delta Base. */
static void test_qpack_base_positive(void)
{
    CHECK(quic_qpack_base(6, 0, 0) == 6);
    CHECK(quic_qpack_base(6, 0, 2) == 8);
}

/* RFC 9204 4.5.1.2: with Sign 1 the Base is RIC minus Delta Base minus 1. */
static void test_qpack_base_negative(void)
{
    CHECK(quic_qpack_base(6, 1, 0) == 5);
    CHECK(quic_qpack_base(6, 1, 2) == 3);
    /* Sign 1, Delta Base RIC-1 yields Base 0, the lowest legal value. */
    CHECK(quic_qpack_base(6, 1, 5) == 0);
}

void test_base(void)
{
    test_qpack_base_positive();
    test_qpack_base_negative();
}

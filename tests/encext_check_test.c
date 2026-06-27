#include "test.h"
#include "tls/encext_check.c"

/* RFC 9001 8.2 */
void test_encext_check(void)
{
    CHECK(quic_encext_has_tp(1) == 1);
    CHECK(quic_encext_has_tp(0) == 0);
    CHECK(quic_encext_has_tp(5) == 1);

    CHECK(quic_encext_required_ok(1) == 1); /* present: ok */
    CHECK(quic_encext_required_ok(0) == 0); /* absent: missing_extension */
}

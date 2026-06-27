#include "test.h"

/* Compatible versions switch without a new handshake; incompatible ones
 * require one. The two predicates are complements. */
void test_compatnego(void)
{
    /* v1 <-> v2 are compatible: switch ok, no retry */
    CHECK(quic_version_compat_switch_ok(QUIC_VERSION_1, QUIC_VERSION_2) == 1);
    CHECK(quic_version_needs_retry(QUIC_VERSION_1, QUIC_VERSION_2) == 0);

    /* same version: compatible with itself */
    CHECK(quic_version_compat_switch_ok(QUIC_VERSION_1, QUIC_VERSION_1) == 1);

    /* unknown negotiated version: not compatible, needs retry */
    CHECK(quic_version_compat_switch_ok(QUIC_VERSION_1, 0xdeadbeefu) == 0);
    CHECK(quic_version_needs_retry(QUIC_VERSION_1, 0xdeadbeefu) == 1);

    /* complement holds for an unknown pair too */
    CHECK(quic_version_compat_switch_ok(0xdeadbeefu, 0xdeadbeefu) == 0);
    CHECK(quic_version_needs_retry(0xdeadbeefu, 0xdeadbeefu) == 1);
}

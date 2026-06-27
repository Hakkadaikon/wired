#include "test.h"

/* RFC 9369 3.1: v1 and v2 are compatible in both directions. */
static void test_v1_v2_compatible(void)
{
    CHECK(quic_version_compatible(QUIC_VERSION_1, QUIC_VERSION_2) == 1);
    CHECK(quic_version_compatible(QUIC_VERSION_2, QUIC_VERSION_1) == 1);
}

/* RFC 9368 2.1: a known version is compatible with itself. */
static void test_self_compatible(void)
{
    CHECK(quic_version_compatible(QUIC_VERSION_1, QUIC_VERSION_1) == 1);
    CHECK(quic_version_compatible(QUIC_VERSION_2, QUIC_VERSION_2) == 1);
}

/* An unknown version has no known compatibility, even with itself. */
static void test_unknown_incompatible(void)
{
    CHECK(quic_version_compatible(0xdeadbeefu, QUIC_VERSION_1) == 0);
    CHECK(quic_version_compatible(QUIC_VERSION_1, 0xdeadbeefu) == 0);
    CHECK(quic_version_compatible(0xdeadbeefu, 0xdeadbeefu) == 0);
}

void test_compat(void)
{
    test_v1_v2_compatible();
    test_self_compatible();
    test_unknown_incompatible();
}

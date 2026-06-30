#include "test.h"

/* RFC 9369 4.1: any version change forces Retry tag re-derivation. */
static void test_retry_reencode_on_change(void)
{
    CHECK(quic_version_retry_reencode(QUIC_VERSION_1, QUIC_VERSION_2) == 1);
    CHECK(quic_version_retry_reencode(QUIC_VERSION_2, QUIC_VERSION_1) == 1);
}

/* No change of version: tag stays valid. */
static void test_retry_no_reencode_same(void)
{
    CHECK(quic_version_retry_reencode(QUIC_VERSION_1, QUIC_VERSION_1) == 0);
    CHECK(quic_version_retry_reencode(0xdeadbeefu, 0xdeadbeefu) == 0);
}

/* RFC 9369 4.1: 0-RTT keys survive a compatible switch and a no-op switch. */
static void test_0rtt_keep_compatible(void)
{
    CHECK(quic_version_0rtt_keep(QUIC_VERSION_1, QUIC_VERSION_2) == 1);
    CHECK(quic_version_0rtt_keep(QUIC_VERSION_1, QUIC_VERSION_1) == 1);
}

/* Incompatible switch (unknown version) discards 0-RTT keys. */
static void test_0rtt_drop_incompatible(void)
{
    CHECK(quic_version_0rtt_keep(QUIC_VERSION_1, 0xdeadbeefu) == 0);
    CHECK(quic_version_0rtt_keep(0xdeadbeefu, 0xdeadbeefu) == 1);
}

void test_switchrule(void)
{
    test_retry_reencode_on_change();
    test_retry_no_reencode_same();
    test_0rtt_keep_compatible();
    test_0rtt_drop_incompatible();
}

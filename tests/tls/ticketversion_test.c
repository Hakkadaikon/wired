#include "test.h"

/* RFC 9369 5: a ticket resumes on the same version. */
static void test_ticket_same_version(void)
{
    CHECK(quic_ticket_version_ok(QUIC_VERSION_1, QUIC_VERSION_1) == 1);
    CHECK(quic_ticket_version_ok(0xdeadbeefu, 0xdeadbeefu) == 1);
}

/* RFC 9369 5: a ticket resumes on a compatible version. */
static void test_ticket_compatible_version(void)
{
    CHECK(quic_ticket_version_ok(QUIC_VERSION_1, QUIC_VERSION_2) == 1);
    CHECK(quic_ticket_version_ok(QUIC_VERSION_2, QUIC_VERSION_1) == 1);
}

/* An incompatible version cannot use the ticket. */
static void test_ticket_incompatible(void)
{
    CHECK(quic_ticket_version_ok(QUIC_VERSION_1, 0xdeadbeefu) == 0);
}

/* RFC 9369 5: 0-RTT requires compatibility; identical-unknown is not. */
static void test_ticket_0rtt(void)
{
    CHECK(quic_ticket_0rtt_ok(QUIC_VERSION_1, QUIC_VERSION_2) == 1);
    CHECK(quic_ticket_0rtt_ok(QUIC_VERSION_1, QUIC_VERSION_1) == 1);
    CHECK(quic_ticket_0rtt_ok(0xdeadbeefu, 0xdeadbeefu) == 0);
    CHECK(quic_ticket_0rtt_ok(QUIC_VERSION_1, 0xdeadbeefu) == 0);
}

void test_ticketversion(void)
{
    test_ticket_same_version();
    test_ticket_compatible_version();
    test_ticket_incompatible();
    test_ticket_0rtt();
}

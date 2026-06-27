#include "test.h"

/* RFC 9002 6.2.4: a fired PTO sends 2 probe packets. */
static void test_probe_count(void)
{
    CHECK(quic_probe_count(1) == 2);
    CHECK(quic_probe_count(0) == 0);
}

/* Probe sent on PTO expiry regardless of bytes in flight. */
static void test_probe_should_send(void)
{
    CHECK(quic_probe_should_send(0, 1) == 1);     /* nothing in flight, still probes */
    CHECK(quic_probe_should_send(1200, 1) == 1);
    CHECK(quic_probe_should_send(1200, 0) == 0);  /* no expiry, no probe */
    CHECK(quic_probe_should_send(0, 0) == 0);
}

void test_probe(void)
{
    test_probe_count();
    test_probe_should_send();
}

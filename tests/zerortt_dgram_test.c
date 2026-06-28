#include "test.h"

/* RFC 9221 3: no remembered support means no 0-RTT DATAGRAM. */
static void test_no_remembered_support(void)
{
    CHECK(quic_datagram_0rtt_ok(0, 0) == 0);
    CHECK(quic_datagram_0rtt_ok(0, 100) == 0);
}

/* A frame within the remembered limit is allowed. */
static void test_within_limit(void)
{
    CHECK(quic_datagram_0rtt_ok(1200, 1) == 1);
    CHECK(quic_datagram_0rtt_ok(1200, 1200) == 1); /* boundary: equal */
}

/* A frame exceeding the remembered limit is rejected. */
static void test_over_limit(void)
{
    CHECK(quic_datagram_0rtt_ok(1200, 1201) == 0); /* boundary: +1 */
}

void test_zerortt_dgram(void)
{
    test_no_remembered_support();
    test_within_limit();
    test_over_limit();
}

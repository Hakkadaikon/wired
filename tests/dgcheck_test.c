#include "test.h"

/* RFC 9221 3: receiving a DATAGRAM without having advertised support is a
 * violation, as is exceeding the advertised size; at-or-under is fine. */
void test_dgcheck(void)
{
    CHECK(quic_datagram_recv_ok(1200, 0, 10) == 0);   /* we did not advertise */
    CHECK(quic_datagram_recv_ok(0, 0, 0) == 0);        /* not advertised at all */
    CHECK(quic_datagram_recv_ok(1200, 1, 1200) == 1);  /* exactly the limit */
    CHECK(quic_datagram_recv_ok(1200, 1, 1201) == 0);  /* over the limit */
    CHECK(quic_datagram_recv_ok(1200, 1, 0) == 1);     /* empty datagram */
}

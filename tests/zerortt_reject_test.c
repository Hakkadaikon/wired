#include "test.h"
#include "tls/zerortt_reject.c"

/* RFC 9001 4.6.1 */
void test_zerortt_reject(void)
{
    int retransmit = 0, discard = 0;
    quic_zerortt_on_reject(&retransmit, &discard);
    CHECK(retransmit == 1);
    CHECK(discard == 1);

    CHECK(quic_zerortt_accepted(1) == 1);
    CHECK(quic_zerortt_accepted(0) == 0);
    CHECK(quic_zerortt_accepted(7) == 1);
}

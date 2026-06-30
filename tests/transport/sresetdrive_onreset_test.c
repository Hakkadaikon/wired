#include "test.h"

/* RFC 9000 10.3: a detected reset closes the connection; otherwise not. */
void test_sresetdrive_onreset(void)
{
    CHECK(quic_sresetdrive_on_detected(1) == 1);
    CHECK(quic_sresetdrive_on_detected(0) == 0);
}

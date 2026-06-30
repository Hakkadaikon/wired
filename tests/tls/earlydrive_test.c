#include "test.h"

/* RFC 9001 4.5: 0-RTT data needs both 0-RTT keys and an offered resumption;
 * either alone is not enough. */
static void test_earlydrive_can_send(void)
{
    CHECK(quic_earlydata_can_send(1, 1) == 1);
    CHECK(quic_earlydata_can_send(1, 0) == 0); /* no resumption */
    CHECK(quic_earlydata_can_send(0, 1) == 0); /* no 0-RTT keys */
    CHECK(quic_earlydata_can_send(0, 0) == 0);
}

/* RFC 9001 4.5 / RFC 8446 2.3: rejected 0-RTT must be resent in 1-RTT;
 * accepted 0-RTT need not be. */
static void test_earlydrive_must_resend(void)
{
    CHECK(quic_earlydata_must_resend(0) == 1); /* server rejected */
    CHECK(quic_earlydata_must_resend(1) == 0); /* server accepted */
}

/* RFC 9000 9.1 / 9.0: migration needs a validated path and a confirmed
 * handshake; neither half alone permits it. */
static void test_earlydrive_can_migrate(void)
{
    CHECK(quic_earlydata_can_migrate(1, 1) == 1);
    CHECK(quic_earlydata_can_migrate(0, 1) == 0); /* path not validated */
    CHECK(quic_earlydata_can_migrate(1, 0) == 0); /* handshake not confirmed */
    CHECK(quic_earlydata_can_migrate(0, 0) == 0);
}

void test_earlydrive(void)
{
    test_earlydrive_can_send();
    test_earlydrive_must_resend();
    test_earlydrive_can_migrate();
}

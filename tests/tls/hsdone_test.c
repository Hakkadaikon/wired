#include "test.h"

/* Completion needs both Finished verified and sent; confirmation is
 * server-side on HANDSHAKE_DONE sent, client-side on received. */
void test_hsdone(void)
{
    CHECK(quic_hs_complete(0, 0) == 0);
    CHECK(quic_hs_complete(1, 0) == 0);
    CHECK(quic_hs_complete(0, 1) == 0);
    CHECK(quic_hs_complete(1, 1) == 1);

    /* server: confirmed iff HANDSHAKE_DONE sent, received irrelevant */
    CHECK(quic_hs_confirmed(1, 0, 0) == 0);
    CHECK(quic_hs_confirmed(1, 0, 1) == 0);
    CHECK(quic_hs_confirmed(1, 1, 0) != 0);

    /* client: confirmed iff HANDSHAKE_DONE received, sent irrelevant */
    CHECK(quic_hs_confirmed(0, 0, 0) == 0);
    CHECK(quic_hs_confirmed(0, 1, 0) == 0);
    CHECK(quic_hs_confirmed(0, 0, 1) != 0);
}

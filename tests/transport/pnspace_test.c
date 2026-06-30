#include "test.h"

/* All spaces start at 0. */
static void test_pnspace_starts_at_zero(void)
{
    quic_pnspace s;
    quic_pnspace_init(&s);
    CHECK(quic_pnspace_next(&s, QUIC_PNS_INITIAL) == 0);
    CHECK(quic_pnspace_next(&s, QUIC_PNS_HANDSHAKE) == 0);
    CHECK(quic_pnspace_next(&s, QUIC_PNS_APP) == 0);
}

/* Each space counts independently: pulling from one does not advance others. */
static void test_pnspace_independent(void)
{
    quic_pnspace s;
    quic_pnspace_init(&s);
    CHECK(quic_pnspace_next(&s, QUIC_PNS_INITIAL) == 0);
    CHECK(quic_pnspace_next(&s, QUIC_PNS_INITIAL) == 1);
    CHECK(quic_pnspace_next(&s, QUIC_PNS_INITIAL) == 2);
    /* Handshake untouched by Initial activity */
    CHECK(quic_pnspace_next(&s, QUIC_PNS_HANDSHAKE) == 0);
    CHECK(quic_pnspace_next(&s, QUIC_PNS_HANDSHAKE) == 1);
    /* App still independent */
    CHECK(quic_pnspace_next(&s, QUIC_PNS_APP) == 0);
    /* Initial resumes from where it left off */
    CHECK(quic_pnspace_next(&s, QUIC_PNS_INITIAL) == 3);
}

void test_pnspace(void)
{
    test_pnspace_starts_at_zero();
    test_pnspace_independent();
}

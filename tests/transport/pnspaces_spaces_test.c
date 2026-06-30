#include "test.h"

/* RFC 9000 12.3: each space numbers from 0 and advances independently. */
static void test_pnspaces_spaces_independent_numbering(void)
{
    quic_pnspaces s;
    quic_pnspaces_init(&s);

    /* Each space starts at 0 and is strictly monotonic. */
    CHECK(quic_pnspaces_next_pn(&s, 0) == 0);
    CHECK(quic_pnspaces_next_pn(&s, 0) == 1);
    CHECK(quic_pnspaces_next_pn(&s, 0) == 2);

    /* Allocating in Initial did not advance Handshake or Application. */
    CHECK(quic_pnspaces_next_pn(&s, 1) == 0); /* Handshake still 0 */
    CHECK(quic_pnspaces_next_pn(&s, 2) == 0); /* Application still 0 */

    /* Cross-checks: spaces stay independent after interleaving. */
    CHECK(quic_pnspaces_next_pn(&s, 1) == 1);
    CHECK(quic_pnspaces_next_pn(&s, 0) == 3); /* Initial resumes from 3 */
    CHECK(quic_pnspaces_next_pn(&s, 2) == 1);
}

void test_pnspaces_spaces(void)
{
    test_pnspaces_spaces_independent_numbering();
}

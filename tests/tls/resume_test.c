#include "test.h"

/* RFC 8446 4.6.1 / RFC 9001 4.6 / RFC 9000 7, 8.1, 17.2.5 */
void test_resume(void)
{
    quic_resume r = {0};
    u8 tk[4] = {1, 2, 3, 4};

    /* store succeeds and records the ticket */
    CHECK(quic_resume_store(&r, tk, sizeof tk, 100, 50, 1000) == 1);
    CHECK(r.have_ticket == 1);
    CHECK(r.ticket_len == 4);
    CHECK(r.ticket[0] == 1 && r.ticket[3] == 4);

    /* RFC 8446 4.6.1: valid within lifetime, boundary at issued_at+lifetime */
    CHECK(quic_resume_valid(&r, 100) == 1);   /* at issuance */
    CHECK(quic_resume_valid(&r, 149) == 1);   /* last valid second */
    CHECK(quic_resume_valid(&r, 150) == 0);   /* boundary: expired */
    CHECK(quic_resume_valid(&r, 200) == 0);   /* well past */

    /* no ticket -> never valid */
    quic_resume empty = {0};
    CHECK(quic_resume_valid(&empty, 0) == 0);

    /* RFC 9000 7.4.1: remembered <= new is compatible, > is not */
    CHECK(quic_resume_tp_compatible(1000, 1000) == 1); /* equal */
    CHECK(quic_resume_tp_compatible(1000, 2000) == 1); /* new larger */
    CHECK(quic_resume_tp_compatible(1000, 999) == 0);  /* new smaller */

    /* RFC 9001 4.6: 0-RTT needs ticket valid AND tp compatible */
    CHECK(quic_resume_can_0rtt(&r, 1, 1) == 1);
    CHECK(quic_resume_can_0rtt(&r, 0, 1) == 0); /* ticket invalid */
    CHECK(quic_resume_can_0rtt(&r, 1, 0) == 0); /* tp incompatible */
    CHECK(quic_resume_can_0rtt(&empty, 1, 1) == 0); /* no ticket */

    /* RFC 9000 8.1 / 17.2.5: Retry does not invalidate resumption */
    CHECK(quic_resume_after_retry(&r, 1) == 1);
    CHECK(quic_resume_after_retry(&r, 0) == 1);
    CHECK(quic_resume_after_retry(&empty, 1) == 0);

    /* RFC 8446 4.6.1: oversized ticket is rejected */
    u8 big[QUIC_RESUME_TICKET_MAX + 1] = {0};
    quic_resume r2 = {0};
    CHECK(quic_resume_store(&r2, big, sizeof big, 0, 10, 0) == 0);
    CHECK(r2.have_ticket == 0);
}

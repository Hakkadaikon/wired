#include "test.h"

/* Issuance stops exactly at the active limit and resumes after retiring. */
static void test_cidpool_limit(void)
{
    quic_cidpool p;
    quic_cidpool_init(&p, 2);
    u64 seq;
    CHECK(quic_cidpool_issue(&p, &seq) == 1 && seq == 0);
    CHECK(quic_cidpool_issue(&p, &seq) == 1 && seq == 1);
    CHECK(quic_cidpool_active_count(&p) == 2);
    /* at the limit: the next issue is refused */
    CHECK(quic_cidpool_issue(&p, &seq) == 0);
    /* retire seq 0, freeing one slot */
    CHECK(quic_cidpool_retire_prior_to(&p, 1) == 1);
    CHECK(quic_cidpool_active_count(&p) == 1);
    CHECK(quic_cidpool_issue(&p, &seq) == 1 && seq == 2);
    CHECK(quic_cidpool_active_count(&p) == 2);
}

/* retire_prior_to is monotone, idempotent, and rejects unissued sequences. */
static void test_cidpool_retire(void)
{
    quic_cidpool p;
    quic_cidpool_init(&p, 5);
    u64 seq;
    for (int i = 0; i < 3; i++) quic_cidpool_issue(&p, &seq); /* seqs 0,1,2 */
    /* retiring past next_seq (3) is a protocol violation */
    CHECK(quic_cidpool_retire_prior_to(&p, 4) == 0);
    /* retire_prior_to exactly next_seq retires all issued so far */
    CHECK(quic_cidpool_retire_prior_to(&p, 3) == 1);
    CHECK(quic_cidpool_active_count(&p) == 0);
    /* a lower retire_prior_to is a no-op success (no floor regression) */
    CHECK(quic_cidpool_retire_prior_to(&p, 1) == 1);
    CHECK(quic_cidpool_active_count(&p) == 0);
}

void test_cidpool(void)
{
    test_cidpool_limit();
    test_cidpool_retire();
}

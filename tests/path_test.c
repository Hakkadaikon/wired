#include "test.h"

/* A path validates only on a matching response to an outstanding challenge. */
static void test_path_validation_match(void)
{
    quic_path p;
    quic_path_init(&p);
    /* no outstanding challenge: a response does not validate */
    CHECK(quic_path_recv_response(&p, 1, 0xABCD) == 0);
    CHECK(p.paths[1].validated == 0);

    quic_path_send_challenge(&p, 1, 0xABCD);
    /* mismatched response does not validate */
    CHECK(quic_path_recv_response(&p, 1, 0x1234) == 0 && p.paths[1].validated == 0);
    /* matching response validates */
    CHECK(quic_path_recv_response(&p, 1, 0xABCD) == 1 && p.paths[1].validated == 1);
}

/* Unvalidated paths cap sends at 3x received; validation lifts the cap. */
static void test_path_anti_amplification(void)
{
    quic_path p;
    quic_path_init(&p);
    p.paths[1].bytes_received = 100;
    CHECK(quic_path_can_send(&p, 1, 300) == 1);  /* exactly 3x */
    CHECK(quic_path_can_send(&p, 1, 301) == 0);  /* 3x + 1 refused */
    /* once validated, the limit is lifted */
    quic_path_send_challenge(&p, 1, 7);
    quic_path_recv_response(&p, 1, 7);
    CHECK(quic_path_can_send(&p, 1, 100000) == 1);
}

/* Migration confirms only after validation and supersedes any prior confirm. */
static void test_path_migration_confirm(void)
{
    quic_path p;
    quic_path_init(&p);
    /* path 1 not yet validated: confirm refused, active unchanged */
    CHECK(quic_path_confirm(&p, 1) == 0 && p.active == 0);

    quic_path_send_challenge(&p, 1, 42);
    quic_path_recv_response(&p, 1, 42);
    CHECK(quic_path_confirm(&p, 1) == 1);
    CHECK(p.active == 1 && p.paths[1].confirmed == 1 && p.paths[0].confirmed == 0);

    /* validate and confirm path 0: it supersedes, clearing path 1's confirm */
    quic_path_send_challenge(&p, 0, 9);
    quic_path_recv_response(&p, 0, 9);
    CHECK(quic_path_confirm(&p, 0) == 1);
    CHECK(p.active == 0 && p.paths[0].confirmed == 1 && p.paths[1].confirmed == 0);
}

/* A duplicate matching response is idempotent. */
static void test_path_idempotent(void)
{
    quic_path p;
    quic_path_init(&p);
    quic_path_send_challenge(&p, 1, 5);
    CHECK(quic_path_recv_response(&p, 1, 5) == 1);
    /* second matching response leaves validated set, no corruption */
    quic_path_recv_response(&p, 1, 5);
    CHECK(p.paths[1].validated == 1);
}

void test_path(void)
{
    test_path_validation_match();
    test_path_anti_amplification();
    test_path_migration_confirm();
    test_path_idempotent();
}

#include "test.h"

/* A path validates only on a matching response to an outstanding challenge. */
static void test_path_validation_match(void) {
  path p;
  path_init(&p);
  /* no outstanding challenge: a response does not validate */
  CHECK(path_recv_response(&p, 1, 0xABCD) == 0);
  CHECK(p.paths[1].validated == 0);

  path_send_challenge(&p, 1, 0xABCD, 0);
  /* mismatched response does not validate */
  CHECK(path_recv_response(&p, 1, 0x1234) == 0 && p.paths[1].validated == 0);
  /* matching response validates */
  CHECK(path_recv_response(&p, 1, 0xABCD) == 1 && p.paths[1].validated == 1);
}

/* Unvalidated paths cap sends at 3x received; validation lifts the cap. */
static void test_path_anti_amplification(void) {
  path p;
  path_init(&p);
  p.paths[1].bytes_received = 100;
  CHECK(path_can_send(&p, 1, 300) == 1); /* exactly 3x */
  CHECK(path_can_send(&p, 1, 301) == 0); /* 3x + 1 refused */
  /* once validated, the limit is lifted */
  path_send_challenge(&p, 1, 7, 0);
  path_recv_response(&p, 1, 7);
  CHECK(path_can_send(&p, 1, 100000) == 1);
}

/* Migration confirms only after validation and supersedes any prior confirm. */
static void test_path_migration_confirm(void) {
  path p;
  path_init(&p);
  /* path 1 not yet validated: confirm refused, active unchanged */
  CHECK(path_confirm(&p, 1) == 0 && p.active == 0);

  path_send_challenge(&p, 1, 42, 0);
  path_recv_response(&p, 1, 42);
  CHECK(path_confirm(&p, 1) == 1);
  CHECK(
      p.active == 1 && p.paths[1].confirmed == 1 && p.paths[0].confirmed == 0);

  /* validate and confirm path 0: it supersedes, clearing path 1's confirm */
  path_send_challenge(&p, 0, 9, 0);
  path_recv_response(&p, 0, 9);
  CHECK(path_confirm(&p, 0) == 1);
  CHECK(
      p.active == 0 && p.paths[0].confirmed == 1 && p.paths[1].confirmed == 0);
}

/* A duplicate matching response is idempotent. */
static void test_path_idempotent(void) {
  path p;
  path_init(&p);
  path_send_challenge(&p, 1, 5, 0);
  CHECK(path_recv_response(&p, 1, 5) == 1);
  /* second matching response leaves validated set, no corruption */
  path_recv_response(&p, 1, 5);
  CHECK(p.paths[1].validated == 1);
}

/* RFC 9000 8.2.4: an endpoint SHOULD abandon path validation based on a
 * timer of three times the larger of the current and new-path PTO. */
static void test_path_abandon_timer(void) {
  path p;
  path_init(&p);
  path_send_challenge(&p, 1, 0xABCD, 1000);
  /* elapsed < 3*pto: still within the window, do not abandon yet */
  CHECK(path_abandon_due(&p, 1, 1000 + 3 * 100 - 1, 100) == 0);
  /* elapsed >= 3*pto: abandon */
  CHECK(path_abandon_due(&p, 1, 1000 + 3 * 100, 100) == 1);
}

/* No outstanding challenge: nothing to abandon. */
static void test_path_abandon_no_challenge(void) {
  path p;
  path_init(&p);
  CHECK(path_abandon_due(&p, 1, 1000000, 100) == 0);
}

/* A validated path never counts as abandonable, no matter the elapsed time.
 */
static void test_path_abandon_not_after_validated(void) {
  path p;
  path_init(&p);
  path_send_challenge(&p, 1, 42, 0);
  path_recv_response(&p, 1, 42);
  CHECK(path_abandon_due(&p, 1, 1000000, 100) == 0);
}

/* RFC 9000 9.3.2: if validation of a new peer address fails, the endpoint
 * reverts to using the last validated peer address. */
static void test_path_revert_on_failure(void) {
  path p;
  path_init(&p);
  /* path 0 (the original) is validated and confirmed first */
  path_send_challenge(&p, 0, 1, 0);
  path_recv_response(&p, 0, 1);
  CHECK(path_confirm(&p, 0) == 1);
  /* migration to path 1 begins but its validation is abandoned */
  path_send_challenge(&p, 1, 2, 0);
  CHECK(path_abandon_due(&p, 1, 1000000, 100) == 1);
  path_revert(&p, 1);
  /* path 1's challenge is cleared and the active path is unchanged (0) */
  CHECK(p.paths[1].challenge == 0);
  CHECK(p.active == 0);
  CHECK(p.paths[0].confirmed == 1);
}

/* Reverting a path with no outstanding challenge is a no-op. */
static void test_path_revert_noop_without_challenge(void) {
  path p;
  path_init(&p);
  path_revert(&p, 1);
  CHECK(p.active == 0);
}

void test_path(void) {
  test_path_validation_match();
  test_path_anti_amplification();
  test_path_migration_confirm();
  test_path_idempotent();
  test_path_abandon_timer();
  test_path_abandon_no_challenge();
  test_path_abandon_not_after_validated();
  test_path_revert_on_failure();
  test_path_revert_noop_without_challenge();
}

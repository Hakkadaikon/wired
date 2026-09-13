#include "test.h"

/* Migration is not handled before the handshake is confirmed. */
static void test_migrate_before_handshake(void) {
  migrate m;
  migrate_init(&m, 100);
  migrate_detect(&m);
  CHECK(m.detected == 0);
}

/* Validation requires both a detected change and a prior PATH_CHALLENGE. */
static void test_migrate_validation_order(void) {
  migrate m;
  migrate_init(&m, 100);
  m.handshake_confirmed = 1;
  CHECK(migrate_validate(&m) == 0);
  migrate_detect(&m);
  CHECK(migrate_validate(&m) == 0);
  migrate_challenge(&m);
  CHECK(migrate_validate(&m) == 1);
  CHECK(m.validated == 1);
}

/* A full migration switches CID and resets congestion/RTT. */
static void test_migrate_full_confirm(void) {
  migrate m;
  migrate_init(&m, 100);
  m.handshake_confirmed = 1;
  migrate_detect(&m);
  migrate_challenge(&m);
  migrate_validate(&m);
  CHECK(migrate_confirm(&m, 100, 0) == 0);
  CHECK(migrate_confirm(&m, 200, 0) == 1);
  CHECK(m.cur_cid == 200 && m.confirmed == 1);
  CHECK(m.cc_reset == 1 && m.port_only == 0);
}

/* A port-only confirm keeps congestion/RTT. */
static void test_migrate_port_only(void) {
  migrate m;
  migrate_init(&m, 100);
  m.handshake_confirmed = 1;
  migrate_detect(&m);
  migrate_challenge(&m);
  migrate_validate(&m);
  CHECK(migrate_confirm(&m, 200, 1) == 1);
  CHECK(m.cc_reset == 0 && m.port_only == 1);
}

/* Confirmation is refused on an unvalidated path. */
static void test_migrate_unvalidated(void) {
  migrate m;
  migrate_init(&m, 100);
  m.handshake_confirmed = 1;
  migrate_detect(&m);
  migrate_challenge(&m);
  CHECK(migrate_confirm(&m, 200, 0) == 0);
  CHECK(m.confirmed == 0);
}

/* RFC 9000 9.3 / 8.2.1: validating one path never validates another. A
 * fresh address change after a confirmed migration must run
 * challenge/validate again before the new path can be confirmed. */
static void test_migrate_new_path_requires_fresh_validation(void) {
  migrate m;
  migrate_init(&m, 100);
  m.handshake_confirmed = 1;
  migrate_detect(&m);
  migrate_challenge(&m);
  migrate_validate(&m);
  CHECK(migrate_confirm(&m, 200, 0) == 1);
  migrate_detect(&m); /* the peer's address changed again */
  CHECK(m.validated == 0);
  CHECK(migrate_confirm(&m, 300, 0) == 0);
  CHECK(m.cur_cid == 200);
  migrate_challenge(&m);
  CHECK(migrate_validate(&m) == 1);
  CHECK(migrate_confirm(&m, 300, 0) == 1);
}

void test_migrate(void) {
  test_migrate_before_handshake();
  test_migrate_validation_order();
  test_migrate_full_confirm();
  test_migrate_port_only();
  test_migrate_unvalidated();
  test_migrate_new_path_requires_fresh_validation();
}

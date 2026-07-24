#include "test.h"

/* A fresh state permits no pushes. */
static void test_push_init(void) {
  quic_h3_push_state s;
  quic_h3_push_init(&s);
  CHECK(quic_h3_push_allowed(&s, 0) == 0);
}

/* Raising the maximum permits IDs strictly below it. */
static void test_push_set_max(void) {
  quic_h3_push_state s;
  quic_h3_push_init(&s);
  CHECK(quic_h3_push_set_max(&s, 3) == 1);
  CHECK(quic_h3_push_allowed(&s, 0) == 1);
  CHECK(quic_h3_push_allowed(&s, 2) == 1);
  CHECK(quic_h3_push_allowed(&s, 3) == 0); /* id == max is not allowed */
}

/* The maximum may be raised again but never lowered. */
static void test_push_monotonic(void) {
  quic_h3_push_state s;
  quic_h3_push_init(&s);
  CHECK(quic_h3_push_set_max(&s, 5) == 1);
  CHECK(quic_h3_push_set_max(&s, 5) == 1);  /* equal holds */
  CHECK(quic_h3_push_set_max(&s, 10) == 1); /* raise */
  CHECK(quic_h3_push_set_max(&s, 9) == 0);  /* lower rejected */
  CHECK(quic_h3_push_allowed(&s, 9) == 1);  /* max unchanged at 10 */
}

/* RFC 9114 7.2.3: a fresh state (max == 0, no MAX_PUSH_ID sent yet) rejects
 * every CANCEL_PUSH -- no Push ID has ever been in range. */
static void test_push_cancel_rejected_before_any_max(void) {
  quic_h3_push_state s;
  quic_h3_push_init(&s);
  CHECK(quic_h3_push_cancel_ok(&s, 0) == 0);
}

/* RFC 9114 7.2.3: CANCEL_PUSH is valid for a Push ID strictly below the
 * granted maximum, and a connection error (H3_ID_ERROR) at or past it --
 * same boundary quic_h3_push_allowed enforces for an outgoing push. */
static void test_push_cancel_in_range_ok(void) {
  quic_h3_push_state s;
  quic_h3_push_init(&s);
  CHECK(quic_h3_push_set_max(&s, 3) == 1);
  CHECK(quic_h3_push_cancel_ok(&s, 0) == 1);
  CHECK(quic_h3_push_cancel_ok(&s, 2) == 1);
  CHECK(quic_h3_push_cancel_ok(&s, 3) == 0);   /* == max: never granted */
  CHECK(quic_h3_push_cancel_ok(&s, 100) == 0); /* well past max */
}

void test_pushid(void) {
  test_push_init();
  test_push_set_max();
  test_push_monotonic();
  test_push_cancel_rejected_before_any_max();
  test_push_cancel_in_range_ok();
}

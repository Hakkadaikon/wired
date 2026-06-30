#include "test.h"

/* RFC 9002 6.2.2.1: arm the PTO timer on Initial/Handshake in-flight data,
 * even under anti-amplification limits (the limit is not an input here). */

static void test_hspto_arm_initial_inflight(void) {
  CHECK(quic_hspto_should_arm(1, 0, 0, 0) == 1);
}

static void test_hspto_arm_handshake_inflight_with_keys(void) {
  CHECK(quic_hspto_should_arm(0, 1, 0, 1) == 1);
}

static void test_hspto_no_arm_handshake_inflight_without_keys(void) {
  CHECK(quic_hspto_should_arm(0, 1, 0, 0) == 0);
}

static void test_hspto_no_arm_when_nothing_inflight(void) {
  CHECK(quic_hspto_should_arm(0, 0, 0, 1) == 0);
}

static void test_hspto_arm_holds_after_confirm_flag(void) {
  /* confirmed flag must not suppress arming while data is in flight. */
  CHECK(quic_hspto_should_arm(1, 0, 1, 1) == 1);
}

void test_hspto_arm(void) {
  test_hspto_arm_initial_inflight();
  test_hspto_arm_handshake_inflight_with_keys();
  test_hspto_no_arm_handshake_inflight_without_keys();
  test_hspto_no_arm_when_nothing_inflight();
  test_hspto_arm_holds_after_confirm_flag();
}

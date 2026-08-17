#include "test.h"

/* RFC 9000 8.1: unvalidated path allows at most 3x received bytes. */
static void test_gate_unvalidated(void) {
  CHECK(udploop_send_allowed(&(pathbudget){100, 0, 0}, 300) == 1);
  CHECK(udploop_send_allowed(&(pathbudget){100, 0, 0}, 301) == 0);
  CHECK(udploop_send_allowed(&(pathbudget){100, 250, 0}, 50) == 1);
  CHECK(udploop_send_allowed(&(pathbudget){100, 250, 0}, 51) == 0);
  CHECK(udploop_send_allowed(&(pathbudget){0, 0, 0}, 1) == 0);
}

/* A validated address has no anti-amplification limit. */
static void test_gate_validated(void) {
  CHECK(udploop_send_allowed(&(pathbudget){0, 0, 1}, 1000) == 1);
  CHECK(udploop_send_allowed(&(pathbudget){100, 9999, 1}, 9999) == 1);
}

void test_antiamp_gate(void) {
  test_gate_unvalidated();
  test_gate_validated();
}

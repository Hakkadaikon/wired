#include "test.h"

static void test_cc_slow_start(void) {
  quic_cc c;
  quic_cc_init(&c);
  u64 start = c.cwnd;
  quic_cc_on_ack(&c, 1200, 10, 10); /* slow start: +acked */
  CHECK(c.cwnd == start + 1200);
}

/* Loss halves cwnd but never below the minimum window (most important). */
static void test_cc_loss_halves_floor(void) {
  quic_cc c;
  quic_cc_init(&c);
  quic_cc_on_loss(&c, 5, 100);
  CHECK(c.cwnd == QUIC_CC_INIT_WINDOW / 2);
  CHECK(c.cwnd >= QUIC_CC_MIN_WINDOW);
  /* drive it down repeatedly: must clamp at the floor */
  for (usz i = 0; i < 20; i++) {
    quic_cc_on_ack(&c, 999999, 1000 + i, 1000 + i); /* exit recovery */
    quic_cc_on_loss(&c, 2000 + i, 2000 + i);
  }
  CHECK(c.cwnd >= QUIC_CC_MIN_WINDOW);
}

/* No window growth while in recovery. */
static void test_cc_no_grow_in_recovery(void) {
  quic_cc c;
  quic_cc_init(&c);
  quic_cc_on_loss(&c, 5, 100); /* enter recovery at t=100 */
  u64 w = c.cwnd;
  quic_cc_on_ack(&c, 1200, 50, 50); /* ack of pre-recovery packet */
  CHECK(c.in_recovery == 1 && c.cwnd == w);
}

/* An ack of a packet sent after recovery began exits recovery. */
static void test_cc_recovery_exit(void) {
  quic_cc c;
  quic_cc_init(&c);
  quic_cc_on_loss(&c, 5, 100);
  quic_cc_on_ack(&c, 1200, 200, 200); /* sent after recovery_start=100 */
  CHECK(c.in_recovery == 0);
}

static void test_cc_persistent_collapse(void) {
  quic_cc c;
  quic_cc_init(&c);
  quic_cc_on_persistent(&c);
  CHECK(c.cwnd == QUIC_CC_MIN_WINDOW);
}

/* CUBIC mode (RFC 9438): loss shrinks by beta_cubic 0.7 and re-anchors the
 * cubic epoch; acks lift cwnd onto the curve — back at W_max when K elapses
 * (W_max 10 segments -> K = cbrt(7.5e9) ms = 1957), convex past it. Slow
 * start before the first loss grows as usual. */
static void test_cc_cubic_mode(void) {
  quic_cc c;
  quic_cc_init_algo(&c, QUIC_CC_ALGO_CUBIC);
  CHECK(c.cwnd == QUIC_CC_INIT_WINDOW);
  quic_cc_on_ack(&c, 1200, 10, 10); /* pre-loss slow start still grows */
  CHECK(c.cwnd == QUIC_CC_INIT_WINDOW + 1200);
  quic_cc_init_algo(&c, QUIC_CC_ALGO_CUBIC);
  quic_cc_on_loss(&c, 1000, 1000);
  CHECK(c.cwnd == 8400); /* 12000 * 0.7 */
  quic_cc_on_ack(&c, 1200, 1500, 1000 + 1957);
  CHECK(c.cwnd == 12000); /* the curve reaches W_max at t = K */
  quic_cc_on_ack(&c, 1200, 1500, 1000 + 1957 + 5000);
  CHECK(c.cwnd == 72000); /* K+5s: 10 + 50 segments, convex growth */
}

void test_cc(void) {
  test_cc_cubic_mode();
  test_cc_slow_start();
  test_cc_loss_halves_floor();
  test_cc_no_grow_in_recovery();
  test_cc_recovery_exit();
  test_cc_persistent_collapse();
}

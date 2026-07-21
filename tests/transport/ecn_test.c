#include "test.h"

/* RFC 9002 7.1.2: counts valid only when neither decreases. */
static void test_ecn_counts_valid(void) {
  CHECK(
      quic_ecn_counts_valid((quic_ecn_counts){0, 0}, (quic_ecn_counts){0, 0}) ==
      1); /* equal is fine */
  CHECK(
      quic_ecn_counts_valid((quic_ecn_counts){3, 7}, (quic_ecn_counts){5, 9}) ==
      1); /* both grow */
  CHECK(
      quic_ecn_counts_valid((quic_ecn_counts){5, 7}, (quic_ecn_counts){3, 9}) ==
      0); /* CE shrank */
  CHECK(
      quic_ecn_counts_valid((quic_ecn_counts){3, 9}, (quic_ecn_counts){5, 7}) ==
      0); /* ECT0 shrank */
  CHECK(
      quic_ecn_counts_valid((quic_ecn_counts){5, 7}, (quic_ecn_counts){5, 7}) ==
      1); /* both equal */
}

static void test_ecn_ce_increased(void) {
  CHECK(quic_ecn_ce_increased(3, 4) == 1);
  CHECK(quic_ecn_ce_increased(3, 3) == 0);
  CHECK(quic_ecn_ce_increased(4, 3) == 0);
}

/* RFC 9002 7.1.2 -- a CE increase is handled as if a packet loss had
 * been detected, so cwnd halves (quic_cc_on_loss's own reduction) and
 * in_recovery is entered exactly as an ordinary loss would do. */
static void test_ecn_on_ce_increase_triggers_congestion_event(void) {
  quic_cc c;
  quic_cc_init(&c);
  u64 cwnd_before = c.cwnd;
  quic_ecn_on_ce_increase(&c, 3, 4, 100, 200);
  CHECK(c.in_recovery == 1);
  CHECK(c.cwnd < cwnd_before);
}

/* Boundary: a CE count that did not increase (unchanged or, per
 * quic_ecn_counts_valid's own contract, never decreasing) triggers no
 * congestion event -- cwnd and in_recovery are left untouched. */
static void test_ecn_on_ce_increase_noop_when_unchanged(void) {
  quic_cc c;
  quic_cc_init(&c);
  u64 cwnd_before = c.cwnd;
  quic_ecn_on_ce_increase(&c, 4, 4, 100, 200);
  CHECK(c.in_recovery == 0);
  CHECK(c.cwnd == cwnd_before);
}

/* RFC 9002 7.1.2 -- ECN counts reported in a received ACK that have
 * regressed (CE or ECT(0) lower than previously observed) must not be
 * applied; quic_ecn_counts_valid is the gate a caller checks before trusting
 * a new counts snapshot enough to feed it to quic_ecn_on_ce_increase at all,
 * so a regressed report never spuriously rewinds the connection's own
 * tracked counts nor (via a rejected update) triggers a bogus congestion
 * event from stale/reordered data. */
static void test_ecn_counts_regression_ignored(void) {
  quic_ecn_counts prev = {5, 7}, regressed_ce = {3, 9}, regressed_ect0 = {5, 4};
  CHECK(quic_ecn_counts_valid(prev, regressed_ce) == 0);
  CHECK(quic_ecn_counts_valid(prev, regressed_ect0) == 0);
}

void test_ecn(void) {
  test_ecn_counts_valid();
  test_ecn_ce_increased();
  test_ecn_on_ce_increase_triggers_congestion_event();
  test_ecn_on_ce_increase_noop_when_unchanged();
  test_ecn_counts_regression_ignored();
}

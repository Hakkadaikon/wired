#include "test.h"

/* RFC 9002 7.1.2: counts valid only when neither decreases. */
static void test_ecn_counts_valid(void) {
  CHECK(
      ecn_counts_valid((ecn_counts){0, 0}, (ecn_counts){0, 0}) ==
      1); /* equal is fine */
  CHECK(
      ecn_counts_valid((ecn_counts){3, 7}, (ecn_counts){5, 9}) ==
      1); /* both grow */
  CHECK(
      ecn_counts_valid((ecn_counts){5, 7}, (ecn_counts){3, 9}) ==
      0); /* CE shrank */
  CHECK(
      ecn_counts_valid((ecn_counts){3, 9}, (ecn_counts){5, 7}) ==
      0); /* ECT0 shrank */
  CHECK(
      ecn_counts_valid((ecn_counts){5, 7}, (ecn_counts){5, 7}) ==
      1); /* both equal */
}

static void test_ecn_ce_increased(void) {
  CHECK(ecn_ce_increased(3, 4) == 1);
  CHECK(ecn_ce_increased(3, 3) == 0);
  CHECK(ecn_ce_increased(4, 3) == 0);
}

/* RFC 9002 7.1.2 -- a CE increase is handled as if a packet loss had
 * been detected, so cwnd halves (cc_on_loss's own reduction) and
 * in_recovery is entered exactly as an ordinary loss would do. */
static void test_ecn_on_ce_increase_triggers_congestion_event(void) {
  cc c;
  cc_init(&c);
  u64 cwnd_before = c.cwnd;
  ecn_on_ce_increase(&c, 3, 4, 100, 200);
  CHECK(c.in_recovery == 1);
  CHECK(c.cwnd < cwnd_before);
}

/* Boundary: a CE count that did not increase (unchanged or, per
 * ecn_counts_valid's own contract, never decreasing) triggers no
 * congestion event -- cwnd and in_recovery are left untouched. */
static void test_ecn_on_ce_increase_noop_when_unchanged(void) {
  cc c;
  cc_init(&c);
  u64 cwnd_before = c.cwnd;
  ecn_on_ce_increase(&c, 4, 4, 100, 200);
  CHECK(c.in_recovery == 0);
  CHECK(c.cwnd == cwnd_before);
}

/* RFC 9002 7.1.2 -- ECN counts reported in a received ACK that have
 * regressed (CE or ECT(0) lower than previously observed) must not be
 * applied; ecn_counts_valid is the gate a caller checks before trusting
 * a new counts snapshot enough to feed it to ecn_on_ce_increase at all,
 * so a regressed report never spuriously rewinds the connection's own
 * tracked counts nor (via a rejected update) triggers a bogus congestion
 * event from stale/reordered data. */
static void test_ecn_counts_regression_ignored(void) {
  ecn_counts prev = {5, 7}, regressed_ce = {3, 9}, regressed_ect0 = {5, 4};
  CHECK(ecn_counts_valid(prev, regressed_ce) == 0);
  CHECK(ecn_counts_valid(prev, regressed_ect0) == 0);
}

/* RFC 9002 8.1 / RFC 9000 13.4.2: a received ACK frame (type 0x03) whose
 * ECN-CE count increased reaches the congestion controller as one
 * congestion event -- and re-delivering the same cumulative counts does
 * not shrink the window a second time. The frame goes through the real
 * ACK codec so the path under test starts at wire bytes. */
static void test_ecn_ce_from_ack_triggers_cc_loss(void) {
  u8        buf[64];
  ack_frame f = {0};
  ack_frame d;
  cc        c;
  ecn_track t;
  f.n_ranges     = 1;
  f.ranges[0].hi = 9;
  f.ranges[0].lo = 0;
  f.has_ecn      = 1;
  f.ect0         = 8;
  f.ce           = 1;
  usz n          = ack_encode(buf, sizeof buf, &f);
  CHECK(n > 0);
  CHECK(ack_decode(buf, n, &d) == n);
  CHECK(d.has_ecn == 1 && d.ce == 1);
  cc_init(&c);
  ecn_track_init(&t);
  u64 cwnd_before = c.cwnd;
  ecn_track_on_counts(
      &t, &c, (ecn_counts){d.ce, d.ect0}, d.ect1, 10, 9, 100, 200);
  CHECK(c.in_recovery == 1);
  CHECK(c.cwnd < cwnd_before);
  CHECK(t.enabled == 1);
  CHECK(t.prev.ce == 1 && t.prev.ect0 == 8);
  /* same cumulative counts again: no new increase, no second shrink */
  u64 cwnd_after = c.cwnd;
  ecn_track_on_counts(
      &t, &c, (ecn_counts){d.ce, d.ect0}, d.ect1, 12, 0, 100, 300);
  CHECK(c.cwnd == cwnd_after);
}

/* RFC 9000 13.4.2.2: an ACK whose ECN counts regressed, whose total
 * exceeds the ECT(0) packets we actually sent, or which reports ECT(1)
 * we never mark, fails validation: ECN is disabled for the connection,
 * the failure is counted, and the congestion controller is untouched. */
static void test_ecn_counts_valid_rejects_decrease_wired(void) {
  cc        c;
  ecn_track t;
  cc_init(&c);
  ecn_track_init(&t);
  ecn_track_on_counts(&t, &c, (ecn_counts){2, 5}, 0, 10, 7, 100, 200);
  CHECK(t.enabled == 1 && t.prev.ce == 2);
  u64 cwnd_before = c.cwnd;
  ecn_track_on_counts(&t, &c, (ecn_counts){1, 6}, 0, 10, 0, 100, 300);
  CHECK(t.enabled == 0);
  CHECK(t.fail_count == 1);
  CHECK(c.cwnd == cwnd_before);
  /* once disabled, even a plausible report is ignored */
  ecn_track_on_counts(&t, &c, (ecn_counts){9, 1}, 0, 10, 0, 100, 400);
  CHECK(t.prev.ce == 2 && t.fail_count == 1);
  /* exceeding the number of ECT packets sent also fails */
  ecn_track_init(&t);
  ecn_track_on_counts(&t, &c, (ecn_counts){3, 8}, 0, 10, 0, 100, 500);
  CHECK(t.enabled == 0 && t.fail_count == 1);
  /* ECT(1) reported while we only ever mark ECT(0) also fails */
  ecn_track_init(&t);
  ecn_track_on_counts(&t, &c, (ecn_counts){0, 4}, 1, 10, 0, 100, 600);
  CHECK(t.enabled == 0 && t.fail_count == 1);
}

/* RFC 9000 13.4.2.1: every packet we send is ECT(0)-marked, so an ACK
 * that acknowledges packets but carries no ECN counts means the peer or
 * path stripped the marks -- ECN is marked unusable. Before anything was
 * sent, a countless ACK proves nothing and changes nothing. */
static void test_ecn_ack_without_counts_marks_ecn_failed(void) {
  ecn_track t;
  ecn_track_init(&t);
  ecn_track_on_missing(&t, 0); /* nothing ECT sent yet: no verdict */
  CHECK(t.enabled == 1 && t.fail_count == 0);
  ecn_track_on_missing(&t, 7);
  CHECK(t.enabled == 0);
  CHECK(t.fail_count == 1);
  ecn_track_on_missing(&t, 8); /* already failed: not recounted */
  CHECK(t.fail_count == 1);
}

/* RFC 9000 13.4.2.1 / RFC 9002 8.3: every packet we send is ECT(0)-marked,
 * so each one is the "probe" 8.3 recommends -- an ACK that newly
 * acknowledges N marked packets must raise ECT(0)+CE by at least N. A peer
 * that suppresses reports (raises the counts by fewer than it newly acked)
 * fails validation: ECN is disabled, the congestion controller untouched,
 * and the sender falls back to loss-based detection alone. Counts MAY
 * exceed the newly acked total (lost ACK frames, 13.4.2.1), so equal and
 * greater increases both pass. */
static void test_ecn_suppressed_counts_fail_validation(void) {
  cc        c;
  ecn_track t;
  cc_init(&c);
  ecn_track_init(&t);
  u64 cwnd_before = c.cwnd;
  /* increase 5 for 5 newly acked: exactly accounted, passes */
  ecn_track_on_counts(&t, &c, (ecn_counts){0, 5}, 0, 20, 5, 100, 200);
  CHECK(t.enabled == 1 && t.prev.ect0 == 5);
  /* increase 6 for 4 newly acked: earlier ACK frames were lost, passes */
  ecn_track_on_counts(&t, &c, (ecn_counts){1, 10}, 0, 20, 4, 100, 300);
  CHECK(t.enabled == 1 && t.prev.ce == 1 && t.prev.ect0 == 10);
  CHECK(c.in_recovery == 1); /* the CE increase still counted */
  /* increase 2 (ect0 +2, ce +0) for 5 newly acked: suppressed, fails */
  c.in_recovery = 0;
  c.cwnd        = cwnd_before;
  ecn_track_on_counts(&t, &c, (ecn_counts){1, 12}, 0, 20, 5, 100, 400);
  CHECK(t.enabled == 0);
  CHECK(t.fail_count == 1);
  CHECK(c.cwnd == cwnd_before && c.in_recovery == 0);
  CHECK(t.prev.ce == 1 && t.prev.ect0 == 10); /* rejected report not kept */
}

/* RFC 9002 8.3 (V-0224): over-reporting ECN-CE only slows the sender, and
 * never past what real congestion could: each valid CE increase is at most
 * one cc_on_loss per recovery period, and cc_on_loss floors the window at
 * kMinimumWindow. A peer inflating CE on every ACK across many recovery
 * periods drives cwnd to exactly CC_MIN_WINDOW, never below, and ECN stays
 * enabled (the reports are self-consistent, so nothing to disable). */
static void test_ecn_inflated_ce_floors_at_min_window(void) {
  cc        c;
  ecn_track t;
  cc_init(&c);
  ecn_track_init(&t);
  for (u64 i = 1; i <= 64; i++) {
    /* each round: one packet newly acked, sent after the last recovery
     * started, so recovery exits and the next CE increase counts again */
    cc_on_ack(&c, 1, 1000 * i, 1000 * i + 1);
    ecn_track_on_counts(
        &t, &c, (ecn_counts){i, 0}, 0, 1000, 1, 1000 * i, 1000 * i + 1);
    CHECK(c.cwnd >= CC_MIN_WINDOW);
  }
  CHECK(c.cwnd == CC_MIN_WINDOW);
  CHECK(t.enabled == 1 && t.prev.ce == 64);
}

void test_ecn(void) {
  test_ecn_counts_valid();
  test_ecn_ce_increased();
  test_ecn_on_ce_increase_triggers_congestion_event();
  test_ecn_on_ce_increase_noop_when_unchanged();
  test_ecn_counts_regression_ignored();
  test_ecn_ce_from_ack_triggers_cc_loss();
  test_ecn_counts_valid_rejects_decrease_wired();
  test_ecn_ack_without_counts_marks_ecn_failed();
  test_ecn_suppressed_counts_fail_validation();
  test_ecn_inflated_ce_floors_at_min_window();
}

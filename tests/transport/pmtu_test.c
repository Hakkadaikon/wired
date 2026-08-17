#include "test.h"

/* Probing starts above the base and the validated PMTU rises as probes are
 * acknowledged. */
static void test_pmtu_grow(void) {
  pmtu p;
  pmtu_init(&p);
  CHECK(p.validated == PMTU_BASE);

  usz probe = pmtu_next_probe(&p, 0);
  CHECK(probe == PMTU_BASE + PMTU_STEP);
  pmtu_on_ack(&p, probe);
  CHECK(p.validated == probe); /* path confirmed at the larger size */
}

/* A single lost probe caps the search (RFC 8899 5.1.3: PROBE_COUNT < MAX_PROBES
 * is not yet a black hole); once the candidate cannot exceed validated,
 * probing stops. Below MAX_PROBES, validated (an already-confirmed size) is
 * untouched -- only a size above it was ruled out. */
static void test_pmtu_loss_caps(void) {
  pmtu p;
  pmtu_init(&p);
  usz probe = pmtu_next_probe(&p, 0);
  pmtu_on_loss(&p, probe); /* this size is too big */
  CHECK(p.ceiling == probe);
  /* the next candidate is the ceiling, not above validated -> search ends */
  CHECK(pmtu_next_probe(&p, 0) == 0);
  CHECK(p.searching == 0);
  CHECK(p.validated == PMTU_BASE); /* never drops below base */
}

/* RFC 8899 5.1.2/5.1.3: PROBE_COUNT increments on loss and resets on ack;
 * fewer than MAX_PROBES losses at the same size keep it retryable. */
static void test_pmtu_probe_count_tracks_losses(void) {
  pmtu p;
  pmtu_init(&p);
  usz probe = pmtu_next_probe(&p, 0);
  CHECK(p.probe_count == 0);
  pmtu_on_loss(&p, probe);
  CHECK(p.probe_count == 1);
  pmtu_on_loss(&p, probe);
  CHECK(p.probe_count == 2);
  CHECK(p.probe_count < PMTU_MAX_PROBES); /* still worth retrying */
}

/* RFC 8899 5.1.2: an ack resets PROBE_COUNT to 0 (a fresh probe cycle). */
static void test_pmtu_ack_resets_probe_count(void) {
  pmtu p;
  pmtu_init(&p);
  usz probe = pmtu_next_probe(&p, 0);
  pmtu_on_loss(&p, probe);
  CHECK(p.probe_count == 1);
  pmtu_on_ack(&p, probe);
  CHECK(p.probe_count == 0);
}

/* RFC 8899 5.1.2/4.3: losing a size above validated MAX_PROBES times in a row
 * (PROBE_COUNT > MAX_PROBES) concludes that size is unsupported, same
 * ceiling-only outcome as a single loss -- validated is untouched because the
 * search never confirmed that larger size to begin with. */
static void test_pmtu_max_probes_above_validated_caps_ceiling_only(void) {
  pmtu p;
  pmtu_init(&p);
  usz probe = pmtu_next_probe(&p, 0);
  int i;
  for (i = 0; i <= PMTU_MAX_PROBES; i++) pmtu_on_loss(&p, probe);
  CHECK(p.ceiling == probe);
  CHECK(p.validated == PMTU_BASE);
  CHECK(pmtu_next_probe(&p, 0) == 0); /* ceiling reached -> search ends */
  CHECK(p.searching == 0);
}

/* RFC 8899 4.3/5.1.2: black hole detection -- losing the CURRENT validated
 * size itself (a confirmation probe at the already-confirmed PLPMTU) MAX_PROBES
 * times in a row means the path no longer supports it; both PLPMTU and MPS
 * (derived from it) must come back down to BASE_PLPMTU, not just cap the
 * ceiling for future growth. */
static void test_pmtu_black_hole_lowers_validated(void) {
  pmtu p;
  pmtu_init(&p);
  usz probe = pmtu_next_probe(&p, 0);
  pmtu_on_ack(&p, probe); /* validated grows past base */
  usz grown = p.validated;
  CHECK(grown > PMTU_BASE);

  int i;
  for (i = 0; i <= PMTU_MAX_PROBES; i++) pmtu_on_loss(&p, grown);
  CHECK(p.validated == PMTU_BASE); /* black hole: PLPMTU drops back */
  CHECK(p.ceiling == grown);       /* the failed size still bounds the search */
}

/* RFC 8899 4.4: the MPS the application may use is the PLPMTU minus this PL's
 * per-datagram overhead (RFC 9000 14.1's 1200-byte floor already nets out
 * IP/UDP framing at the base, so the derivation is a flat per-datagram
 * subtraction on top of that). */
static void test_pmtu_mps(void) {
  pmtu p;
  pmtu_init(&p);
  CHECK(pmtu_mps(&p) == PMTU_BASE - PMTU_OVERHEAD);
  pmtu_on_ack(&p, PMTU_BASE + PMTU_STEP);
  CHECK(pmtu_mps(&p) == PMTU_BASE + PMTU_STEP - PMTU_OVERHEAD);
}

/* Probing climbs to the ceiling then stops. */
static void test_pmtu_reaches_max(void) {
  pmtu p;
  pmtu_init(&p);
  usz probe;
  int steps = 0;
  while ((probe = pmtu_next_probe(&p, 0)) != 0 && steps < 100) {
    pmtu_on_ack(&p, probe);
    steps++;
  }
  CHECK(p.validated <= PMTU_MAX && p.validated >= PMTU_BASE);
  CHECK(pmtu_next_probe(&p, 0) == 0); /* done */
}

/* RFC 8899 5.1.1: PROBE_TIMER MUST NOT be smaller than 1s and SHOULD be
 * larger than 15s; this SDK's value satisfies both. */
static void test_pmtu_probe_timer_value_meets_rfc_floor(void) {
  CHECK(PMTU_PROBE_TIMER_US >= 1000000); /* MUST NOT be < 1s */
  CHECK(PMTU_PROBE_TIMER_US > 15000000); /* SHOULD be > 15s */
}

/* No probe outstanding: the PROBE_TIMER is never due. */
static void test_pmtu_probe_timer_not_due_without_probe(void) {
  pmtu p;
  pmtu_init(&p);
  CHECK(pmtu_probe_timer_due(&p, PMTU_PROBE_TIMER_US * 10) == 0);
}

/* A probe outstanding: due only once PMTU_PROBE_TIMER_US has elapsed
 * since it was sent, not before. */
static void test_pmtu_probe_timer_due_after_elapsed(void) {
  pmtu p;
  pmtu_init(&p);
  pmtu_next_probe(&p, 1000);
  CHECK(pmtu_probe_timer_due(&p, 1000 + PMTU_PROBE_TIMER_US - 1) == 0);
  CHECK(pmtu_probe_timer_due(&p, 1000 + PMTU_PROBE_TIMER_US) == 1);
}

/* An acked or lost probe cancels the PROBE_TIMER (RFC 8899 5.1.1: "The timer
 * is canceled when the PL receives acknowledgment"). */
static void test_pmtu_probe_timer_canceled_on_resolve(void) {
  pmtu p;
  pmtu_init(&p);
  usz probe = pmtu_next_probe(&p, 1000);
  pmtu_on_ack(&p, probe);
  CHECK(pmtu_probe_timer_due(&p, 1000 + PMTU_PROBE_TIMER_US) == 0);
}

/* RFC 8899 5.2: still Search Complete's PMTU_RAISE_TIMER is never due while
 * still actively searching. */
static void test_pmtu_raise_timer_not_due_while_searching(void) {
  pmtu p;
  pmtu_init(&p);
  CHECK(pmtu_raise_timer_due(&p, (u64)PMTU_RAISE_TIMER_US * 10) == 0);
}

/* Once the search concludes, the PMTU_RAISE_TIMER (600s) fires only after
 * that much time has passed since Search Complete was reached. */
static void test_pmtu_raise_timer_due_after_elapsed(void) {
  pmtu p;
  pmtu_init(&p);
  usz probe = pmtu_next_probe(&p, 100);
  pmtu_on_loss(&p, probe); /* this size is too big -> caps the search */
  CHECK(pmtu_next_probe(&p, 100) == 0); /* search concluded at t=100 */
  CHECK(p.searching == 0);
  CHECK(pmtu_raise_timer_due(&p, 100 + PMTU_RAISE_TIMER_US - 1) == 0);
  CHECK(pmtu_raise_timer_due(&p, 100 + PMTU_RAISE_TIMER_US) == 1);
}

/* RFC 8899 5.2: resuming the search clears the prior round's ceiling/lost
 * bound and PROBE_COUNT so a fresh, larger candidate can be probed again. */
static void test_pmtu_resume_search_clears_bounds(void) {
  pmtu p;
  pmtu_init(&p);
  usz probe = pmtu_next_probe(&p, 0);
  pmtu_on_loss(&p, probe);
  CHECK(pmtu_next_probe(&p, 0) == 0); /* Search Complete */
  CHECK(p.searching == 0);

  pmtu_resume_search(&p);
  CHECK(p.searching == 1);
  CHECK(p.ceiling == PMTU_MAX);
  CHECK(p.lost == 0);
  CHECK(p.probe_count == 0);
  CHECK(pmtu_next_probe(&p, 0) != 0); /* searching again */
}

/* RFC 8899 3.7: raising the PLPMTU (and so the MPS, RFC 8899 4.4) must never
 * itself grow the congestion window measured in bytes -- cwnd growth is
 * governed only by RFC 9002 7's ack-driven algorithm. cc structurally
 * cannot read pmtu (cc.h includes only bbr.h), so this pins that a probe
 * ack that raises validated/MPS leaves an independently-held cc's cwnd
 * byte-for-byte unchanged. */
static void test_pmtu_ack_does_not_grow_cc_cwnd(void) {
  pmtu p;
  cc   c;
  pmtu_init(&p);
  cc_init(&c);
  u64 cwnd_before = c.cwnd;
  u64 mps_before  = pmtu_mps(&p);

  usz probe = pmtu_next_probe(&p, 0);
  pmtu_on_ack(&p, probe);

  CHECK(pmtu_mps(&p) > mps_before); /* PLPMTU/MPS did rise */
  CHECK(c.cwnd == cwnd_before);     /* cwnd did not */
}

void test_pmtu(void) {
  test_pmtu_grow();
  test_pmtu_loss_caps();
  test_pmtu_reaches_max();
  test_pmtu_probe_count_tracks_losses();
  test_pmtu_ack_resets_probe_count();
  test_pmtu_max_probes_above_validated_caps_ceiling_only();
  test_pmtu_black_hole_lowers_validated();
  test_pmtu_mps();
  test_pmtu_probe_timer_value_meets_rfc_floor();
  test_pmtu_probe_timer_not_due_without_probe();
  test_pmtu_probe_timer_due_after_elapsed();
  test_pmtu_probe_timer_canceled_on_resolve();
  test_pmtu_raise_timer_not_due_while_searching();
  test_pmtu_raise_timer_due_after_elapsed();
  test_pmtu_resume_search_clears_bounds();
  test_pmtu_ack_does_not_grow_cc_cwnd();
}

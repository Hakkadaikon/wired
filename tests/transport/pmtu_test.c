#include "test.h"

/* Probing starts above the base and the validated PMTU rises as probes are
 * acknowledged. */
static void test_pmtu_grow(void) {
  quic_pmtu p;
  quic_pmtu_init(&p);
  CHECK(p.validated == QUIC_PMTU_BASE);

  usz probe = quic_pmtu_next_probe(&p, 0);
  CHECK(probe == QUIC_PMTU_BASE + QUIC_PMTU_STEP);
  quic_pmtu_on_ack(&p, probe);
  CHECK(p.validated == probe); /* path confirmed at the larger size */
}

/* A single lost probe caps the search (RFC 8899 5.1.3: PROBE_COUNT < MAX_PROBES
 * is not yet a black hole); once the candidate cannot exceed validated,
 * probing stops. Below MAX_PROBES, validated (an already-confirmed size) is
 * untouched -- only a size above it was ruled out. */
static void test_pmtu_loss_caps(void) {
  quic_pmtu p;
  quic_pmtu_init(&p);
  usz probe = quic_pmtu_next_probe(&p, 0);
  quic_pmtu_on_loss(&p, probe); /* this size is too big */
  CHECK(p.ceiling == probe);
  /* the next candidate is the ceiling, not above validated -> search ends */
  CHECK(quic_pmtu_next_probe(&p, 0) == 0);
  CHECK(p.searching == 0);
  CHECK(p.validated == QUIC_PMTU_BASE); /* never drops below base */
}

/* RFC 8899 5.1.2/5.1.3: PROBE_COUNT increments on loss and resets on ack;
 * fewer than MAX_PROBES losses at the same size keep it retryable. */
static void test_pmtu_probe_count_tracks_losses(void) {
  quic_pmtu p;
  quic_pmtu_init(&p);
  usz probe = quic_pmtu_next_probe(&p, 0);
  CHECK(p.probe_count == 0);
  quic_pmtu_on_loss(&p, probe);
  CHECK(p.probe_count == 1);
  quic_pmtu_on_loss(&p, probe);
  CHECK(p.probe_count == 2);
  CHECK(p.probe_count < QUIC_PMTU_MAX_PROBES); /* still worth retrying */
}

/* RFC 8899 5.1.2: an ack resets PROBE_COUNT to 0 (a fresh probe cycle). */
static void test_pmtu_ack_resets_probe_count(void) {
  quic_pmtu p;
  quic_pmtu_init(&p);
  usz probe = quic_pmtu_next_probe(&p, 0);
  quic_pmtu_on_loss(&p, probe);
  CHECK(p.probe_count == 1);
  quic_pmtu_on_ack(&p, probe);
  CHECK(p.probe_count == 0);
}

/* RFC 8899 5.1.2/4.3: losing a size above validated MAX_PROBES times in a row
 * (PROBE_COUNT > MAX_PROBES) concludes that size is unsupported, same
 * ceiling-only outcome as a single loss -- validated is untouched because the
 * search never confirmed that larger size to begin with. */
static void test_pmtu_max_probes_above_validated_caps_ceiling_only(void) {
  quic_pmtu p;
  quic_pmtu_init(&p);
  usz probe = quic_pmtu_next_probe(&p, 0);
  int i;
  for (i = 0; i <= QUIC_PMTU_MAX_PROBES; i++) quic_pmtu_on_loss(&p, probe);
  CHECK(p.ceiling == probe);
  CHECK(p.validated == QUIC_PMTU_BASE);
  CHECK(quic_pmtu_next_probe(&p, 0) == 0); /* ceiling reached -> search ends */
  CHECK(p.searching == 0);
}

/* RFC 8899 4.3/5.1.2: black hole detection -- losing the CURRENT validated
 * size itself (a confirmation probe at the already-confirmed PLPMTU) MAX_PROBES
 * times in a row means the path no longer supports it; both PLPMTU and MPS
 * (derived from it) must come back down to BASE_PLPMTU, not just cap the
 * ceiling for future growth. */
static void test_pmtu_black_hole_lowers_validated(void) {
  quic_pmtu p;
  quic_pmtu_init(&p);
  usz probe = quic_pmtu_next_probe(&p, 0);
  quic_pmtu_on_ack(&p, probe); /* validated grows past base */
  usz grown = p.validated;
  CHECK(grown > QUIC_PMTU_BASE);

  int i;
  for (i = 0; i <= QUIC_PMTU_MAX_PROBES; i++) quic_pmtu_on_loss(&p, grown);
  CHECK(p.validated == QUIC_PMTU_BASE); /* black hole: PLPMTU drops back */
  CHECK(p.ceiling == grown); /* the failed size still bounds the search */
}

/* RFC 8899 4.4: the MPS the application may use is the PLPMTU minus this PL's
 * per-datagram overhead (RFC 9000 14.1's 1200-byte floor already nets out
 * IP/UDP framing at the base, so the derivation is a flat per-datagram
 * subtraction on top of that). */
static void test_pmtu_mps(void) {
  quic_pmtu p;
  quic_pmtu_init(&p);
  CHECK(quic_pmtu_mps(&p) == QUIC_PMTU_BASE - QUIC_PMTU_OVERHEAD);
  quic_pmtu_on_ack(&p, QUIC_PMTU_BASE + QUIC_PMTU_STEP);
  CHECK(
      quic_pmtu_mps(&p) ==
      QUIC_PMTU_BASE + QUIC_PMTU_STEP - QUIC_PMTU_OVERHEAD);
}

/* Probing climbs to the ceiling then stops. */
static void test_pmtu_reaches_max(void) {
  quic_pmtu p;
  quic_pmtu_init(&p);
  usz probe;
  int steps = 0;
  while ((probe = quic_pmtu_next_probe(&p, 0)) != 0 && steps < 100) {
    quic_pmtu_on_ack(&p, probe);
    steps++;
  }
  CHECK(p.validated <= QUIC_PMTU_MAX && p.validated >= QUIC_PMTU_BASE);
  CHECK(quic_pmtu_next_probe(&p, 0) == 0); /* done */
}

/* RFC 8899 5.1.1: PROBE_TIMER MUST NOT be smaller than 1s and SHOULD be
 * larger than 15s; this SDK's value satisfies both. */
static void test_pmtu_probe_timer_value_meets_rfc_floor(void) {
  CHECK(QUIC_PMTU_PROBE_TIMER_US >= 1000000); /* MUST NOT be < 1s */
  CHECK(QUIC_PMTU_PROBE_TIMER_US > 15000000); /* SHOULD be > 15s */
}

/* No probe outstanding: the PROBE_TIMER is never due. */
static void test_pmtu_probe_timer_not_due_without_probe(void) {
  quic_pmtu p;
  quic_pmtu_init(&p);
  CHECK(quic_pmtu_probe_timer_due(&p, QUIC_PMTU_PROBE_TIMER_US * 10) == 0);
}

/* A probe outstanding: due only once QUIC_PMTU_PROBE_TIMER_US has elapsed
 * since it was sent, not before. */
static void test_pmtu_probe_timer_due_after_elapsed(void) {
  quic_pmtu p;
  quic_pmtu_init(&p);
  quic_pmtu_next_probe(&p, 1000);
  CHECK(
      quic_pmtu_probe_timer_due(&p, 1000 + QUIC_PMTU_PROBE_TIMER_US - 1) == 0);
  CHECK(quic_pmtu_probe_timer_due(&p, 1000 + QUIC_PMTU_PROBE_TIMER_US) == 1);
}

/* An acked or lost probe cancels the PROBE_TIMER (RFC 8899 5.1.1: "The timer
 * is canceled when the PL receives acknowledgment"). */
static void test_pmtu_probe_timer_canceled_on_resolve(void) {
  quic_pmtu p;
  quic_pmtu_init(&p);
  usz probe = quic_pmtu_next_probe(&p, 1000);
  quic_pmtu_on_ack(&p, probe);
  CHECK(quic_pmtu_probe_timer_due(&p, 1000 + QUIC_PMTU_PROBE_TIMER_US) == 0);
}

/* RFC 8899 5.2: still Search Complete's PMTU_RAISE_TIMER is never due while
 * still actively searching. */
static void test_pmtu_raise_timer_not_due_while_searching(void) {
  quic_pmtu p;
  quic_pmtu_init(&p);
  CHECK(quic_pmtu_raise_timer_due(&p, (u64)QUIC_PMTU_RAISE_TIMER_US * 10) == 0);
}

/* Once the search concludes, the PMTU_RAISE_TIMER (600s) fires only after
 * that much time has passed since Search Complete was reached. */
static void test_pmtu_raise_timer_due_after_elapsed(void) {
  quic_pmtu p;
  quic_pmtu_init(&p);
  usz probe = quic_pmtu_next_probe(&p, 100);
  quic_pmtu_on_loss(&p, probe); /* this size is too big -> caps the search */
  CHECK(quic_pmtu_next_probe(&p, 100) == 0); /* search concluded at t=100 */
  CHECK(p.searching == 0);
  CHECK(quic_pmtu_raise_timer_due(&p, 100 + QUIC_PMTU_RAISE_TIMER_US - 1) == 0);
  CHECK(quic_pmtu_raise_timer_due(&p, 100 + QUIC_PMTU_RAISE_TIMER_US) == 1);
}

/* RFC 8899 5.2: resuming the search clears the prior round's ceiling/lost
 * bound and PROBE_COUNT so a fresh, larger candidate can be probed again. */
static void test_pmtu_resume_search_clears_bounds(void) {
  quic_pmtu p;
  quic_pmtu_init(&p);
  usz probe = quic_pmtu_next_probe(&p, 0);
  quic_pmtu_on_loss(&p, probe);
  CHECK(quic_pmtu_next_probe(&p, 0) == 0); /* Search Complete */
  CHECK(p.searching == 0);

  quic_pmtu_resume_search(&p);
  CHECK(p.searching == 1);
  CHECK(p.ceiling == QUIC_PMTU_MAX);
  CHECK(p.lost == 0);
  CHECK(p.probe_count == 0);
  CHECK(quic_pmtu_next_probe(&p, 0) != 0); /* searching again */
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
}

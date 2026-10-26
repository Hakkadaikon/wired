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

/* Lose the probe of `size` PMTU_MAX_PROBES times in a row (RFC 8899 5.1.2:
 * the point at which the size is concluded unsupported). */
static void pmtu_lose_max(pmtu* p, usz size) {
  for (int i = 0; i < PMTU_MAX_PROBES; i++) {
    pmtu_on_loss(p, size);
  }
}

/* RFC 8899 5.2/5.3.3: a lost probe is retried -- PROBE_COUNT < MAX_PROBES
 * re-offers the same size (a loss for any other reason must not end the
 * search); the MAX_PROBES-th loss caps the ceiling, and once the candidate
 * cannot exceed validated, probing stops. validated is never touched. */
static void test_pmtu_loss_retries_until_max_probes(void) {
  pmtu p;
  pmtu_init(&p);
  usz probe = pmtu_next_probe(&p, 0);
  for (int i = 1; i < PMTU_MAX_PROBES; i++) {
    pmtu_on_loss(&p, probe);
    CHECK(p.ceiling == PMTU_MAX);           /* not concluded yet */
    CHECK(pmtu_next_probe(&p, 0) == probe); /* the same size again */
  }
  pmtu_on_loss(&p, probe);
  CHECK(p.ceiling == probe);
  CHECK(pmtu_next_probe(&p, 0) == 0); /* candidate == lost: search ends */
  CHECK(p.phase == PMTU_PHASE_COMPLETE);
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
  pmtu_on_loss(&p, probe);
  CHECK(p.probe_count == 0); /* the verdict starts a fresh count */
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

/* RFC 8899 4.3/5.1.2: black hole detection -- losing a probe at the CURRENT
 * validated size MAX_PROBES times in a row means the path no longer supports
 * it; PLPMTU and MPS come back down to BASE_PLPMTU and the BASE phase then
 * confirms it with a BASE_PLPMTU probe (RFC 8899 5.2). */
static void test_pmtu_black_hole_lowers_validated(void) {
  pmtu p;
  pmtu_init(&p);
  usz probe = pmtu_next_probe(&p, 0);
  pmtu_on_ack(&p, probe); /* validated grows past base */
  usz grown = p.validated;
  CHECK(grown > PMTU_BASE);

  pmtu_lose_max(&p, grown);
  CHECK(p.validated == PMTU_BASE); /* black hole: PLPMTU drops back */
  CHECK(pmtu_mps(&p) == PMTU_BASE - PMTU_OVERHEAD);
  CHECK(p.ceiling == grown); /* the failed size still bounds the search */
  CHECK(p.phase == PMTU_PHASE_BASE);
  CHECK(pmtu_next_probe(&p, 0) == PMTU_BASE);
}

/* RFC 8899 4.3 (excessive loss of data of the PLPMTU size): above-base data
 * packets lost MAX_PROBES times with no newer one acked is a black hole; an
 * ack of a newer one resets the count, and a loss older than it is not
 * evidence at all (pmtu_big_suspect). */
static void test_pmtu_big_losses_black_hole(void) {
  pmtu p;
  pmtu_init(&p);
  pmtu_on_ack(&p, PMTU_BASE + PMTU_STEP);
  pmtu_on_big_losses(&p, PMTU_MAX_PROBES - 1);
  pmtu_on_big_ack(&p, 10);
  CHECK(pmtu_big_suspect(&p, 9) == 0);
  CHECK(pmtu_big_suspect(&p, 11) == 1);
  pmtu_on_big_losses(&p, PMTU_MAX_PROBES - 1);
  CHECK(p.validated == PMTU_BASE + PMTU_STEP); /* the ack reset the count */
  pmtu_on_big_losses(&p, 1);
  CHECK(p.validated == PMTU_BASE);
  CHECK(p.phase == PMTU_PHASE_BASE);
}

/* At the base there is no larger size to blame: data losses never drop the
 * PLPMTU or leave SEARCHING (RFC 8899 4.3 applies to the current PLPMTU). */
static void test_pmtu_big_losses_ignored_at_base(void) {
  pmtu p;
  pmtu_init(&p);
  pmtu_on_big_losses(&p, PMTU_MAX_PROBES);
  CHECK(p.phase == PMTU_PHASE_SEARCHING);
  pmtu_on_big_losses(&p, 0);
  CHECK(p.big_lost == 0);
}

/* RFC 8899 5.2 BASE: BASE_PLPMTU lost MAX_PROBES times -> ERROR, where only
 * BASE_PLPMTU probes may go out (RFC 9000 14: pmtu_halted); an acked one
 * returns to SEARCHING. */
static void test_pmtu_base_failure_enters_error(void) {
  pmtu p;
  pmtu_init(&p);
  pmtu_on_ack(&p, PMTU_BASE + PMTU_STEP);
  pmtu_lose_max(&p, p.validated); /* black hole -> BASE */
  CHECK(pmtu_halted(&p) == 0);
  CHECK(pmtu_next_probe(&p, 0) == PMTU_BASE);
  pmtu_lose_max(&p, PMTU_BASE);
  CHECK(p.phase == PMTU_PHASE_ERROR);
  CHECK(pmtu_halted(&p) == 1);
  CHECK(pmtu_next_probe(&p, 0) == PMTU_BASE);
  pmtu_lose_max(&p, PMTU_BASE);
  CHECK(p.phase == PMTU_PHASE_ERROR); /* still probing */
  CHECK(pmtu_next_probe(&p, 0) == PMTU_BASE);
  pmtu_on_ack(&p, PMTU_BASE);
  CHECK(p.phase == PMTU_PHASE_SEARCHING);
  CHECK(pmtu_halted(&p) == 0);
}

/* RFC 8899 3.5/5.1.2: MAX_PLPMTU follows the local link, clamped to the
 * [BASE, PMTU_MAX] range this SDK's buffers carry, and a resumed search
 * goes back to that ceiling, not PMTU_MAX. */
static void test_pmtu_set_max_caps_search(void) {
  pmtu p;
  pmtu_init(&p);
  pmtu_set_max(&p, PMTU_BASE + 10);
  CHECK(p.ceiling == PMTU_BASE + 10);
  CHECK(pmtu_next_probe(&p, 0) == PMTU_BASE + 10);
  pmtu_lose_max(&p, PMTU_BASE + 10);
  CHECK(pmtu_next_probe(&p, 0) == 0);
  pmtu_resume_search(&p);
  CHECK(p.ceiling == PMTU_BASE + 10);
  pmtu_set_max(&p, 100);
  CHECK(p.max == PMTU_BASE);
  pmtu_set_max(&p, 65536);
  CHECK(p.max == PMTU_MAX);
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
  pmtu_lose_max(&p, probe); /* this size is too big -> caps the search */
  CHECK(pmtu_next_probe(&p, 100) == 0); /* search concluded at t=100 */
  CHECK(p.phase == PMTU_PHASE_COMPLETE);
  CHECK(pmtu_raise_timer_due(&p, 100 + PMTU_RAISE_TIMER_US - 1) == 0);
  CHECK(pmtu_raise_timer_due(&p, 100 + PMTU_RAISE_TIMER_US) == 1);
}

/* RFC 8899 5.2: resuming the search clears the prior round's ceiling/lost
 * bound and PROBE_COUNT so a fresh, larger candidate can be probed again. */
static void test_pmtu_resume_search_clears_bounds(void) {
  pmtu p;
  pmtu_init(&p);
  usz probe = pmtu_next_probe(&p, 0);
  pmtu_lose_max(&p, probe);
  CHECK(pmtu_next_probe(&p, 0) == 0); /* Search Complete */
  CHECK(p.phase == PMTU_PHASE_COMPLETE);

  pmtu_resume_search(&p);
  CHECK(p.phase == PMTU_PHASE_SEARCHING);
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

/* One row of the RFC 8899 5.2 state x event table: from `from` (validated
 * one step above the base), apply `ev` to the phase's own probe and expect
 * the next probe size `next` and then phase `to` (asking for the next probe
 * is what concludes a capped search). */
typedef struct {
  int from;
  int ev;
  int to;
  usz next;
} pmtu_row;

#define PMTU_EV_ACK 0     /* the phase's own probe acked */
#define PMTU_EV_LOSS1 1   /* that probe lost once */
#define PMTU_EV_LOSSMAX 2 /* that probe lost MAX_PROBES times */
#define PMTU_EV_BIGLOSS 3 /* MAX_PROBES above-base data packets lost */
#define PMTU_EV_RAISE 4   /* PMTU_RAISE_TIMER expiry handled */

#define PMTU_V1 (PMTU_BASE + PMTU_STEP)
#define PMTU_V2 (PMTU_BASE + 2 * PMTU_STEP)

/* The size the phase probes (the validated size in SEARCH_COMPLETE, where
 * only a loss at the PLPMTU itself is meaningful). */
static usz pmtu_row_size(pmtu* p) {
  usz n = pmtu_next_probe(p, 0);
  return n ? n : p->validated;
}

static void pmtu_row_apply(pmtu* p, int ev, usz size) {
  if (ev == PMTU_EV_ACK) {
    pmtu_on_ack(p, size);
  } else if (ev == PMTU_EV_LOSS1) {
    pmtu_on_loss(p, size);
  } else if (ev == PMTU_EV_LOSSMAX) {
    pmtu_lose_max(p, size);
  } else if (ev == PMTU_EV_BIGLOSS) {
    pmtu_on_big_losses(p, PMTU_MAX_PROBES);
  } else if (pmtu_raise_timer_due(p, (u64)PMTU_RAISE_TIMER_US)) {
    pmtu_resume_search(p);
  }
}

static void test_pmtu_state_event_table(void) {
  static const pmtu_row rows[] = {
      {PMTU_PHASE_DISABLED, PMTU_EV_ACK, PMTU_PHASE_DISABLED, 0},
      {PMTU_PHASE_DISABLED, PMTU_EV_LOSS1, PMTU_PHASE_DISABLED, 0},
      {PMTU_PHASE_DISABLED, PMTU_EV_LOSSMAX, PMTU_PHASE_DISABLED, 0},
      {PMTU_PHASE_DISABLED, PMTU_EV_BIGLOSS, PMTU_PHASE_DISABLED, 0},
      {PMTU_PHASE_DISABLED, PMTU_EV_RAISE, PMTU_PHASE_DISABLED, 0},
      {PMTU_PHASE_BASE, PMTU_EV_ACK, PMTU_PHASE_SEARCHING, PMTU_V2},
      {PMTU_PHASE_BASE, PMTU_EV_LOSS1, PMTU_PHASE_BASE, PMTU_BASE},
      {PMTU_PHASE_BASE, PMTU_EV_LOSSMAX, PMTU_PHASE_ERROR, PMTU_BASE},
      {PMTU_PHASE_BASE, PMTU_EV_BIGLOSS, PMTU_PHASE_BASE, PMTU_BASE},
      {PMTU_PHASE_BASE, PMTU_EV_RAISE, PMTU_PHASE_BASE, PMTU_BASE},
      {PMTU_PHASE_SEARCHING, PMTU_EV_ACK, PMTU_PHASE_SEARCHING,
       PMTU_V2 + PMTU_STEP},
      {PMTU_PHASE_SEARCHING, PMTU_EV_LOSS1, PMTU_PHASE_SEARCHING, PMTU_V2},
      {PMTU_PHASE_SEARCHING, PMTU_EV_LOSSMAX, PMTU_PHASE_COMPLETE, 0},
      {PMTU_PHASE_SEARCHING, PMTU_EV_BIGLOSS, PMTU_PHASE_BASE, PMTU_BASE},
      {PMTU_PHASE_SEARCHING, PMTU_EV_RAISE, PMTU_PHASE_SEARCHING, PMTU_V2},
      {PMTU_PHASE_COMPLETE, PMTU_EV_ACK, PMTU_PHASE_COMPLETE, 0},
      {PMTU_PHASE_COMPLETE, PMTU_EV_LOSS1, PMTU_PHASE_COMPLETE, 0},
      {PMTU_PHASE_COMPLETE, PMTU_EV_LOSSMAX, PMTU_PHASE_BASE, PMTU_BASE},
      {PMTU_PHASE_COMPLETE, PMTU_EV_BIGLOSS, PMTU_PHASE_BASE, PMTU_BASE},
      {PMTU_PHASE_COMPLETE, PMTU_EV_RAISE, PMTU_PHASE_SEARCHING, PMTU_V2},
      {PMTU_PHASE_ERROR, PMTU_EV_ACK, PMTU_PHASE_SEARCHING, PMTU_V2},
      {PMTU_PHASE_ERROR, PMTU_EV_LOSS1, PMTU_PHASE_ERROR, PMTU_BASE},
      {PMTU_PHASE_ERROR, PMTU_EV_LOSSMAX, PMTU_PHASE_ERROR, PMTU_BASE},
      {PMTU_PHASE_ERROR, PMTU_EV_BIGLOSS, PMTU_PHASE_ERROR, PMTU_BASE},
      {PMTU_PHASE_ERROR, PMTU_EV_RAISE, PMTU_PHASE_ERROR, PMTU_BASE},
  };
  for (usz i = 0; i < sizeof rows / sizeof rows[0]; i++) {
    pmtu p;
    pmtu_init(&p);
    p.validated = PMTU_V1;
    p.phase     = rows[i].from;
    pmtu_row_apply(&p, rows[i].ev, pmtu_row_size(&p));
    CHECK(pmtu_next_probe(&p, 0) == rows[i].next);
    CHECK(p.phase == rows[i].to);
  }
}

void test_pmtu(void) {
  test_pmtu_grow();
  test_pmtu_loss_retries_until_max_probes();
  test_pmtu_reaches_max();
  test_pmtu_probe_count_tracks_losses();
  test_pmtu_ack_resets_probe_count();
  test_pmtu_black_hole_lowers_validated();
  test_pmtu_big_losses_black_hole();
  test_pmtu_big_losses_ignored_at_base();
  test_pmtu_base_failure_enters_error();
  test_pmtu_set_max_caps_search();
  test_pmtu_state_event_table();
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

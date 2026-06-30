#include "test.h"

/* Probing starts above the base and the validated PMTU rises as probes are
 * acknowledged. */
static void test_pmtu_grow(void) {
  quic_pmtu p;
  quic_pmtu_init(&p);
  CHECK(p.validated == QUIC_PMTU_BASE);

  usz probe = quic_pmtu_next_probe(&p);
  CHECK(probe == QUIC_PMTU_BASE + QUIC_PMTU_STEP);
  quic_pmtu_on_ack(&p, probe);
  CHECK(p.validated == probe); /* path confirmed at the larger size */
}

/* A lost probe caps the search; once the candidate cannot exceed validated,
 * probing stops. */
static void test_pmtu_loss_caps(void) {
  quic_pmtu p;
  quic_pmtu_init(&p);
  usz probe = quic_pmtu_next_probe(&p);
  quic_pmtu_on_loss(&p, probe); /* this size is too big */
  CHECK(p.ceiling == probe);
  /* the next candidate is the ceiling, not above validated -> search ends */
  CHECK(quic_pmtu_next_probe(&p) == 0);
  CHECK(p.searching == 0);
  CHECK(p.validated == QUIC_PMTU_BASE); /* never drops below base */
}

/* Probing climbs to the ceiling then stops. */
static void test_pmtu_reaches_max(void) {
  quic_pmtu p;
  quic_pmtu_init(&p);
  usz probe;
  int steps = 0;
  while ((probe = quic_pmtu_next_probe(&p)) != 0 && steps < 100) {
    quic_pmtu_on_ack(&p, probe);
    steps++;
  }
  CHECK(p.validated <= QUIC_PMTU_MAX && p.validated >= QUIC_PMTU_BASE);
  CHECK(quic_pmtu_next_probe(&p) == 0); /* done */
}

void test_pmtu(void) {
  test_pmtu_grow();
  test_pmtu_loss_caps();
  test_pmtu_reaches_max();
}

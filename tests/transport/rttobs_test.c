#include "test.h"

/* RFC 9312 3.5: an edge is a change in the spin value. */
static void test_rttobs_edge(void) {
  CHECK(quic_rttobs_is_edge(0, 1) == 1);
  CHECK(quic_rttobs_is_edge(1, 0) == 1);
  CHECK(quic_rttobs_is_edge(0, 0) == 0);
  CHECK(quic_rttobs_is_edge(1, 1) == 0);
}

/* A sample needs spin enabled and an observed edge. */
static void test_rttobs_sample(void) {
  CHECK(quic_rttobs_sample_ok(1, 1) == 1);
  CHECK(quic_rttobs_sample_ok(0, 1) == 0); /* spin off */
  CHECK(quic_rttobs_sample_ok(1, 0) == 0); /* no edge */
  CHECK(quic_rttobs_sample_ok(0, 0) == 0);
}

void test_rttobs(void) {
  test_rttobs_edge();
  test_rttobs_sample();
}

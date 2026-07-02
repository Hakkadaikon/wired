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

void test_ecn(void) {
  test_ecn_counts_valid();
  test_ecn_ce_increased();
}

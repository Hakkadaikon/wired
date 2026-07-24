#include "test.h"

/* First sample seeds smoothed_rtt and min_rtt to the sample (RFC 9002 5.2). */
static void test_rtt_first_sample(void) {
  quic_rtt r;
  quic_rtt_init(&r);
  quic_rtt_sample(&r, 100000, 0, 0, 0);
  CHECK(r.smoothed_rtt == 100000 && r.min_rtt == 100000);
  CHECK(r.rttvar == 50000);
}

/* Constant samples keep smoothed_rtt pinned at that value (convex bound). */
static void test_rtt_constant_stays(void) {
  quic_rtt r;
  quic_rtt_init(&r);
  quic_rtt_sample(&r, 80000, 0, 0, 0);
  for (usz i = 0; i < 20; i++) quic_rtt_sample(&r, 80000, 0, 0, 0);
  CHECK(r.smoothed_rtt == 80000); /* lo==hi: no integer-division drift */
}

/* Samples within [lo,hi] keep smoothed_rtt within [lo,hi] (prover R0-R3). */
static void test_rtt_within_bounds(void) {
  quic_rtt r;
  quic_rtt_init(&r);
  u64 lo = 50000, hi = 150000;
  quic_rtt_sample(&r, lo, 0, 0, 0);
  u64 seq[] = {hi, lo, hi, hi, lo, 100000, hi, lo};
  for (usz i = 0; i < sizeof(seq) / sizeof(seq[0]); i++) {
    quic_rtt_sample(&r, seq[i], 0, 0, 0);
    CHECK(r.smoothed_rtt >= lo && r.smoothed_rtt <= hi);
  }
}

/* PTO = smoothed + max(4*rttvar, granularity) + max_ack_delay. */
static void test_rtt_pto(void) {
  quic_rtt r;
  quic_rtt_init(&r);
  quic_rtt_sample(&r, 100000, 0, 0, 0); /* smoothed=100000, rttvar=50000 */
  CHECK(quic_rtt_pto(&r, 25000) == 100000 + 200000 + 25000);
}

/* RFC 9002 5.3: before handshake confirmation, max_ack_delay is ignored, so
 * a large ack_delay is applied unclamped (9002-015). */
static void test_rtt_sample_ignores_max_ack_delay_before_confirm(void) {
  quic_rtt r;
  quic_rtt_init(&r);
  quic_rtt_sample(&r, 100000, 0, 0, 0); /* seed: min_rtt=100000 */
  /* ack_delay(40000) > max_ack_delay(25000), but not confirmed: use 40000
   * unclamped. adjusted_rtt = 150000 - 40000 = 110000. */
  quic_rtt_sample(&r, 150000, 40000, 25000, 0);
  u64 want_var = quic_u64_absdiff(100000, 110000);
  CHECK(r.rttvar == (3 * 50000 + want_var) / 4);
  CHECK(r.smoothed_rtt == (7 * 100000 + 110000) / 8);
}

/* RFC 9002 5.3: after confirmation, ack_delay > max_ack_delay is clamped to
 * max_ack_delay (9002-016). */
static void test_rtt_sample_clamps_ack_delay_after_confirm(void) {
  quic_rtt r;
  quic_rtt_init(&r);
  quic_rtt_sample(&r, 100000, 0, 0, 1); /* seed: min_rtt=100000 */
  /* ack_delay(40000) > max_ack_delay(25000), confirmed: clamp to 25000.
   * adjusted_rtt = 150000 - 25000 = 125000. */
  quic_rtt_sample(&r, 150000, 40000, 25000, 1);
  u64 want_var = quic_u64_absdiff(100000, 125000);
  CHECK(r.rttvar == (3 * 50000 + want_var) / 4);
  CHECK(r.smoothed_rtt == (7 * 100000 + 125000) / 8);
}

/* RFC 9002 5.3: after confirmation, ack_delay < max_ack_delay is used as-is
 * (the min() picks ack_delay, not the clamp) (9002-016). */
static void test_rtt_sample_uses_ack_delay_after_confirm_when_smaller(void) {
  quic_rtt r;
  quic_rtt_init(&r);
  quic_rtt_sample(&r, 100000, 0, 0, 1); /* seed: min_rtt=100000 */
  /* ack_delay(10000) < max_ack_delay(25000), confirmed: use 10000.
   * adjusted_rtt = 150000 - 10000 = 140000. */
  quic_rtt_sample(&r, 150000, 10000, 25000, 1);
  u64 want_var = quic_u64_absdiff(100000, 140000);
  CHECK(r.rttvar == (3 * 50000 + want_var) / 4);
  CHECK(r.smoothed_rtt == (7 * 100000 + 140000) / 8);
}

void test_rtt(void) {
  test_rtt_first_sample();
  test_rtt_constant_stays();
  test_rtt_within_bounds();
  test_rtt_pto();
  test_rtt_sample_ignores_max_ack_delay_before_confirm();
  test_rtt_sample_clamps_ack_delay_after_confirm();
  test_rtt_sample_uses_ack_delay_after_confirm_when_smaller();
}

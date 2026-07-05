#include "transport/recovery/congestion/cc/hystart.h"

#include "test.h"

/* Feed n identical samples inside one round (packet numbers below the round
 * boundary), returning the last verdict. */
static int hs_feed(quic_hystart* h, u64 rtt, u64 pn0, int n, u64 next_pn) {
  int exit_now = 0;
  for (int i = 0; i < n; i++)
    exit_now = quic_hystart_sample(h, rtt, pn0 + (u64)i, next_pn);
  return exit_now;
}

/* The first round can never exit (no previous round to compare against),
 * however many samples arrive. */
static void test_hystart_first_round_never_exits(void) {
  quic_hystart h;
  quic_hystart_init(&h);
  CHECK(hs_feed(&h, 100, 0, 10, 100) == 0);
}

/* Stable RTT across rounds stays in slow start; a jump past the threshold
 * (eta = clamp(4, last/8, 16); last 40 -> eta 5) with at least 8 samples in
 * the round exits. */
static void test_hystart_exit_on_rtt_increase(void) {
  quic_hystart h;
  quic_hystart_init(&h);
  /* round 1: min 40, ends at pn 10 (next_pn recorded as boundary) */
  CHECK(hs_feed(&h, 40, 0, 8, 10) == 0);
  /* round 2 (acked pn >= 10 rolls the round): stable 41 < 40+5: stays */
  CHECK(hs_feed(&h, 41, 10, 8, 20) == 0);
  /* round 3: 47 >= 41 + 5: exits after the 8th sample */
  CHECK(hs_feed(&h, 47, 20, 7, 30) == 0); /* 7 samples: not yet */
  CHECK(quic_hystart_sample(&h, 47, 27, 30) == 1);
}

/* Fewer than 8 samples in the round never exits, whatever the jump. */
static void test_hystart_needs_eight_samples(void) {
  quic_hystart h;
  quic_hystart_init(&h);
  CHECK(hs_feed(&h, 10, 0, 8, 10) == 0);
  CHECK(hs_feed(&h, 500, 10, 7, 20) == 0);
}

/* The threshold clamps: last 200 -> eta 16 (cap), last 8 -> eta 4 (floor). */
static void test_hystart_eta_clamps(void) {
  quic_hystart h;
  quic_hystart_init(&h);
  CHECK(hs_feed(&h, 200, 0, 8, 10) == 0);
  /* 215 < 200+16: no exit; 216 >= 200+16: exit */
  CHECK(hs_feed(&h, 215, 10, 8, 20) == 0);
  quic_hystart_init(&h);
  CHECK(hs_feed(&h, 200, 0, 8, 10) == 0);
  CHECK(hs_feed(&h, 216, 10, 8, 20) == 1);
  quic_hystart_init(&h);
  CHECK(hs_feed(&h, 8, 0, 8, 10) == 0);
  CHECK(hs_feed(&h, 12, 10, 8, 20) == 1); /* 12 >= 8+4 (floored eta) */
}

void test_hystart(void) {
  test_hystart_first_round_never_exits();
  test_hystart_exit_on_rtt_increase();
  test_hystart_needs_eight_samples();
  test_hystart_eta_clamps();
}

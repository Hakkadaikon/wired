#include "transport/recovery/congestion/cc/hystart.h"

#include "test.h"

/* Feed n identical samples inside one round (packet numbers below the round
 * boundary), returning the last verdict. */
static int hs_feed(hystart* h, u64 rtt, u64 pn0, int n, u64 next_pn) {
  int exit_now = 0;
  for (int i = 0; i < n; i++) {
    exit_now = hystart_sample(h, rtt, pn0 + (u64)i, next_pn);
  }
  return exit_now;
}

/* The first round can never exit (no previous round to compare against),
 * however many samples arrive. */
static void test_hystart_first_round_never_exits(void) {
  hystart h;
  hystart_init(&h);
  CHECK(hs_feed(&h, 100, 0, 10, 100) == 0);
}

/* Stable RTT across rounds stays in slow start; a jump past the threshold
 * (eta = clamp(4, last/8, 16); last 40 -> eta 5) with at least 8 samples in
 * the round enters Conservative Slow Start (RFC 9406 4.2), not avoidance:
 * the verdict stays 0 and the round's min becomes the CSS baseline. */
static void test_hystart_css_on_rtt_increase(void) {
  hystart h;
  hystart_init(&h);
  /* round 1: min 40, ends at pn 10 (next_pn recorded as boundary) */
  CHECK(hs_feed(&h, 40, 0, 8, 10) == 0);
  /* round 2 (acked pn >= 10 rolls the round): stable 41 < 40+5: stays */
  CHECK(hs_feed(&h, 41, 10, 8, 20) == 0);
  /* round 3: 47 >= 41 + 5: exits after the 8th sample */
  CHECK(hs_feed(&h, 47, 20, 7, 30) == 0); /* 7 samples: not yet */
  CHECK(h.css == 0);
  CHECK(hystart_sample(&h, 47, 27, 30) == 0);
  CHECK(h.css == 1);
  CHECK(h.css_baseline == 47);
}

/* Enter CSS: round 1 min 40, round 2 min 50 (>= 40 + 5). */
static void hs_enter_css(hystart* h) {
  hystart_init(h);
  CHECK(hs_feed(h, 40, 0, 8, 10) == 0);
  CHECK(hs_feed(h, 50, 10, 8, 20) == 0);
  CHECK(h->css == 1);
}

/* RFC 9406 4.2: in CSS, a round whose min RTT (over at least 8 samples)
 * drops below the CSS baseline resumes slow start. */
static void test_hystart_css_resumes_slow_start(void) {
  hystart h;
  hs_enter_css(&h);
  CHECK(hs_feed(&h, 49, 20, 7, 30) == 0);
  CHECK(h.css == 1); /* 7 samples: not yet */
  CHECK(hystart_sample(&h, 49, 27, 30) == 0);
  CHECK(h.css == 0);
}

/* RFC 9406 4.2: CSS_ROUNDS (5) rounds in CSS without the RTT falling back
 * end slow start (verdict 1: the caller sets ssthresh = cwnd). */
static void test_hystart_css_rounds_exit(void) {
  hystart h;
  hs_enter_css(&h);
  for (u64 r = 2; r < 6; r++) {
    CHECK(hs_feed(&h, 50, r * 10, 8, r * 10 + 10) == 0);
  }
  CHECK(hystart_sample(&h, 50, 60, 70) == 1); /* 5th round boundary */
}

/* RFC 9406 4.2: in CSS cwnd grows by acked / CSS_GROWTH_DIVISOR (4). */
static void test_hystart_css_growth(void) {
  hystart h;
  hystart_init(&h);
  CHECK(hystart_acked(&h, 1200) == 1200);
  hs_enter_css(&h);
  CHECK(hystart_acked(&h, 1200) == 300);
}

/* Fewer than 8 samples in the round never exits, whatever the jump. */
static void test_hystart_needs_eight_samples(void) {
  hystart h;
  hystart_init(&h);
  CHECK(hs_feed(&h, 10, 0, 8, 10) == 0);
  CHECK(hs_feed(&h, 500, 10, 7, 20) == 0);
}

/* The threshold clamps: last 200 -> eta 16 (cap), last 8 -> eta 4 (floor). */
static void test_hystart_eta_clamps(void) {
  hystart h;
  hystart_init(&h);
  CHECK(hs_feed(&h, 200, 0, 8, 10) == 0);
  /* 215 < 200+16: no exit; 216 >= 200+16: exit */
  CHECK(hs_feed(&h, 215, 10, 8, 20) == 0);
  CHECK(h.css == 0);
  hystart_init(&h);
  CHECK(hs_feed(&h, 200, 0, 8, 10) == 0);
  CHECK(hs_feed(&h, 216, 10, 8, 20) == 0);
  CHECK(h.css == 1);
  hystart_init(&h);
  CHECK(hs_feed(&h, 8, 0, 8, 10) == 0);
  CHECK(hs_feed(&h, 12, 10, 8, 20) == 0); /* 12 >= 8+4 (floored eta) */
  CHECK(h.css == 1);
}

void test_hystart(void) {
  test_hystart_first_round_never_exits();
  test_hystart_css_on_rtt_increase();
  test_hystart_css_resumes_slow_start();
  test_hystart_css_rounds_exit();
  test_hystart_css_growth();
  test_hystart_needs_eight_samples();
  test_hystart_eta_clamps();
}

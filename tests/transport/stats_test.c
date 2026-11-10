#include "test.h"

static void test_stats_rtt_get(void) {
  rtt r;
  rtt_init(&r);
  rtt_sample(&r, 100000, 0, 0, 0);
  stats_rtt out;
  stats_rtt_get(&r, &out);
  CHECK(out.smoothed_rtt == r.smoothed_rtt);
  CHECK(out.min_rtt == r.min_rtt);
  CHECK(out.rttvar == r.rttvar);
}

static void test_stats_cc_get(void) {
  cc c;
  cc_init(&c);
  cc_on_loss(&c, 0, 1000);
  stats_cc out;
  stats_cc_get(&c, &out);
  CHECK(out.cwnd == c.cwnd);
  CHECK(out.ssthresh == c.ssthresh);
  CHECK(out.in_recovery == c.in_recovery);
}

void test_stats(void) {
  test_stats_rtt_get();
  test_stats_cc_get();
}

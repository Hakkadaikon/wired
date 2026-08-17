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

static void test_stats_sent_get_empty(void) {
  sent s;
  sent_init(&s);
  stats_sent out;
  stats_sent_get(&s, &out);
  CHECK(out.bytes_in_flight == 0);
  CHECK(out.lost == 0);
}

static void test_stats_sent_get_inflight_and_loss(void) {
  sent s;
  sent_init(&s);
  sent_out p1 = {.pn = 0, .size = 100, .time_sent = 0};
  sent_out p2 = {.pn = 1, .size = 200, .time_sent = 0};
  sent_out p3 = {.pn = 2, .size = 300, .time_sent = 0};
  sent_out p4 = {.pn = 3, .size = 400, .time_sent = 0};
  CHECK(sent_on_send(&s, &p1));
  CHECK(sent_on_send(&s, &p2));
  CHECK(sent_on_send(&s, &p3));
  CHECK(sent_on_send(&s, &p4));
  sent_on_ack(&s, 3); /* largest_acked=3, pn=0 now >= threshold(3) behind */
  CHECK(sent_detect_loss(&s) == 1); /* pn=0 lost */

  stats_sent out;
  stats_sent_get(&s, &out);
  CHECK(out.bytes_in_flight == s.bytes_in_flight);
  CHECK(out.lost == 1);
}

void test_stats(void) {
  test_stats_rtt_get();
  test_stats_cc_get();
  test_stats_sent_get_empty();
  test_stats_sent_get_inflight_and_loss();
}

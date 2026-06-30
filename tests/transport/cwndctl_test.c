#include "test.h"

/* RFC 9002 7.5: admission boundary at the window edge. */
static void test_cwndctl_can_send_boundary(void) {
  CHECK(quic_cwndctl_can_send(1000, 1500, 500) == 1); /* exactly fills cwnd */
  CHECK(quic_cwndctl_can_send(1000, 1500, 501) == 0); /* one byte over */
  CHECK(quic_cwndctl_can_send(0, 1500, 1500) == 1);   /* whole window free */
  CHECK(quic_cwndctl_can_send(1500, 1500, 1) == 0);   /* already full */
}

/* RFC 9002 7.7: interval = 5 * mtu * srtt / (4 * cwnd). */
static void test_cwndctl_pacing_interval(void) {
  /* 5 * 1200 * 8000 / (4 * 12000) = 1000 us */
  CHECK(quic_cwndctl_pacing_interval(8000, 12000, 1200) == 1000);
  CHECK(quic_cwndctl_pacing_interval(8000, 0, 1200) == 0); /* cwnd 0 */
}

void test_cwndctl(void) {
  test_cwndctl_can_send_boundary();
  test_cwndctl_pacing_interval();
}

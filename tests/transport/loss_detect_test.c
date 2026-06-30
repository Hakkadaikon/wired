#include "test.h"

/* Packet threshold = 3. pn 3+ below largest_acked is lost; 2 below is not. */
static void test_loss_packet_threshold(void) {
  quic_sentpkt t;
  quic_sentpkt_init(&t);
  quic_sentpkt_on_send(&t, 1, 1000, 1, 1); /* 4 below 5 -> lost */
  quic_sentpkt_on_send(&t, 2, 1000, 1, 1); /* 3 below 5 -> lost (boundary) */
  quic_sentpkt_on_send(&t, 3, 1000, 1, 1); /* 2 below 5 -> NOT lost */
  u64 lost[8];
  usz n = 0;
  /* now==sent, large loss_delay: time threshold inert, isolate packet */
  quic_loss_detect(&t, 5, 1000, 5000, lost, &n);
  CHECK(n == 2);
  CHECK(t.e[0].state == QUIC_SP_LOST);
  CHECK(t.e[1].state == QUIC_SP_LOST);
  CHECK(t.e[2].state == QUIC_SP_INFLIGHT);
}

/* Time threshold: a packet older than now-loss_delay is lost even within
 * the packet threshold. */
static void test_loss_time_threshold(void) {
  quic_sentpkt t;
  quic_sentpkt_init(&t);
  quic_sentpkt_on_send(&t, 5, 100, 1, 1); /* sent at t=100, 0 below largest */
  u64 lost[4];
  usz n = 0;
  quic_loss_detect(&t, 5, 1000, 500, lost, &n); /* now-delay=500 > 100 */
  CHECK(n == 1);
  CHECK(t.e[0].state == QUIC_SP_LOST);
}

/* Within both thresholds: not lost. */
static void test_loss_none(void) {
  quic_sentpkt t;
  quic_sentpkt_init(&t);
  quic_sentpkt_on_send(&t, 4, 900, 1, 1); /* 1 below 5, recent */
  u64 lost[4];
  usz n = 99;
  quic_loss_detect(&t, 5, 1000, 500, lost, &n);
  CHECK(n == 0);
  CHECK(t.e[0].state == QUIC_SP_INFLIGHT);
}

void test_loss_detect(void) {
  test_loss_packet_threshold();
  test_loss_time_threshold();
  test_loss_none();
}

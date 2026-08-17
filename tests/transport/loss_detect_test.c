#include "test.h"

/* Packet threshold = 3. pn 3+ below largest_acked is lost; 2 below is not. */
static void test_loss_packet_threshold(void) {
  sentpkt t;
  sentpkt_init(&t);
  sentpkt_on_send(&t, &(sentpkt_out){1, 1000, 1, 1}); /* 4 below 5 -> lost */
  sentpkt_on_send(
      &t, &(sentpkt_out){2, 1000, 1, 1}); /* 3 below 5 -> lost (boundary) */
  sentpkt_on_send(
      &t, &(sentpkt_out){3, 1000, 1, 1}); /* 2 below 5 -> NOT lost */
  u64 lost[8];
  usz n = 0;
  /* now==sent, large loss_delay: time threshold inert, isolate packet */
  loss_detect(&t, &(loss_params){5, 1000, 5000}, (u64out){lost, &n});
  CHECK(n == 2);
  CHECK(t.e[0].state == QUIC_SP_LOST);
  CHECK(t.e[1].state == QUIC_SP_LOST);
  CHECK(t.e[2].state == QUIC_SP_INFLIGHT);
}

/* Time threshold: a packet older than now-loss_delay is lost even within
 * the packet threshold. */
static void test_loss_time_threshold(void) {
  sentpkt t;
  sentpkt_init(&t);
  sentpkt_on_send(
      &t, &(sentpkt_out){5, 100, 1, 1}); /* sent at t=100, 0 below largest */
  u64 lost[4];
  usz n = 0;
  loss_detect(
      &t, &(loss_params){5, 1000, 500},
      (u64out){lost, &n}); /* now-delay=500 > 100 */
  CHECK(n == 1);
  CHECK(t.e[0].state == QUIC_SP_LOST);
}

/* Within both thresholds: not lost. */
static void test_loss_none(void) {
  sentpkt t;
  sentpkt_init(&t);
  sentpkt_on_send(&t, &(sentpkt_out){4, 900, 1, 1}); /* 1 below 5, recent */
  u64 lost[4];
  usz n = 99;
  loss_detect(&t, &(loss_params){5, 1000, 500}, (u64out){lost, &n});
  CHECK(n == 0);
  CHECK(t.e[0].state == QUIC_SP_INFLIGHT);
}

/* RFC 9002 7.4: an endpoint MUST NOT ignore the loss of a packet sent after
 * the earliest acknowledged packet in the space (9002-059). Here pn 10 was
 * sent well after the earliest acknowledged packet (pn 1, implied by
 * largest_acked's ack range starting there) yet still crosses the packet
 * threshold against a later largest_acked (13) -- loss_detect has no
 * undecryptable-packet exemption at all, so it is still declared lost, not
 * skipped. */
static void test_loss_not_ignored_after_earliest_acked(void) {
  sentpkt t;
  sentpkt_init(&t);
  sentpkt_on_send(
      &t, &(sentpkt_out){10, 100, 1, 1}); /* sent after pn 1's ack */
  u64 lost[4];
  usz n = 0;
  /* now==sent, large loss_delay: isolate the packet-threshold path. */
  loss_detect(&t, &(loss_params){13, 100, 5000}, (u64out){lost, &n});
  CHECK(n == 1);
  CHECK(lost[0] == 10);
  CHECK(t.e[0].state == QUIC_SP_LOST);
}

void test_loss_detect(void) {
  test_loss_packet_threshold();
  test_loss_time_threshold();
  test_loss_none();
  test_loss_not_ignored_after_earliest_acked();
}

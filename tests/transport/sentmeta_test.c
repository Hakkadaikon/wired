#include "test.h"

static void test_sentmeta_on_sent_adds_inflight(void) {
  quic_sentmeta m;
  quic_sentmeta_init(&m);

  CHECK(
      quic_sentmeta_on_sent(&m, &(quic_sentmeta_out){0, 100, 1, 1, 1200}) == 1);
  CHECK(m.count == 1);
  CHECK(m.total_in_flight == 1200);
}

static void test_sentmeta_on_sent_non_inflight_no_bytes(void) {
  quic_sentmeta m;
  quic_sentmeta_init(&m);

  /* ACK-only packet: ack_eliciting=0, in_flight=0 -> no bytes counted. */
  CHECK(quic_sentmeta_on_sent(&m, &(quic_sentmeta_out){5, 100, 0, 0, 40}) == 1);
  CHECK(m.count == 1);
  CHECK(m.total_in_flight == 0);
}

static void test_sentmeta_on_ack_subtracts_and_returns_time(void) {
  quic_sentmeta       m;
  quic_sentmeta_acked out = {0, -1};
  quic_sentmeta_init(&m);

  quic_sentmeta_on_sent(&m, &(quic_sentmeta_out){7, 555, 1, 1, 1000});
  CHECK(quic_sentmeta_on_ack(&m, 7, &out) == 1);
  CHECK(out.rtt_sample_time_sent == 555);
  CHECK(out.was_ack_eliciting == 1);
  CHECK(m.total_in_flight == 0);
  CHECK(m.count == 0);
}

static void test_sentmeta_on_ack_unknown_pn(void) {
  quic_sentmeta       m;
  quic_sentmeta_acked out = {42, 9};
  quic_sentmeta_init(&m);

  quic_sentmeta_on_sent(&m, &(quic_sentmeta_out){1, 10, 1, 1, 500});
  CHECK(quic_sentmeta_on_ack(&m, 99, &out) == 0);
  CHECK(out.rtt_sample_time_sent == 42); /* outputs untouched */
  CHECK(out.was_ack_eliciting == 9);
  CHECK(m.total_in_flight == 500);
}

static void test_sentmeta_loss_packet_threshold_boundary(void) {
  quic_sentmeta m;
  u64           lost[QUIC_SENTMETA_CAP];
  usz           n = 0;
  quic_sentmeta_init(&m);

  quic_sentmeta_on_sent(
      &m, &(quic_sentmeta_out){10, 0, 1, 1, 100}); /* largest_acked - 2 */
  quic_sentmeta_on_sent(
      &m, &(quic_sentmeta_out){9, 0, 1, 1, 100}); /* largest_acked - 3 */

  /* largest_acked=12, huge loss_delay so only packet threshold fires. */
  quic_sentmeta_detect_loss(
      &m, &(quic_sentmeta_loss_in){12, 0, 1000000},
      (quic_sentmeta_u64out){lost, &n});
  CHECK(n == 1); /* pn 9 lost (12-9>=3), pn 10 not (12-10<3) */
  CHECK(lost[0] == 9);
  CHECK(m.total_in_flight == 100);
}

static void test_sentmeta_loss_time_threshold_boundary(void) {
  quic_sentmeta m;
  u64           lost[QUIC_SENTMETA_CAP];
  usz           n = 0;
  quic_sentmeta_init(&m);

  quic_sentmeta_on_sent(&m, &(quic_sentmeta_out){0, 100, 1, 1, 200});

  /* now=149, loss_delay=50 -> 149 < 150, not lost. largest_acked far below. */
  quic_sentmeta_detect_loss(
      &m, &(quic_sentmeta_loss_in){0, 149, 50},
      (quic_sentmeta_u64out){lost, &n});
  CHECK(n == 0);
  CHECK(m.total_in_flight == 200);

  /* now=150 -> 150 >= 100+50, lost. */
  quic_sentmeta_detect_loss(
      &m, &(quic_sentmeta_loss_in){0, 150, 50},
      (quic_sentmeta_u64out){lost, &n});
  CHECK(n == 1);
  CHECK(lost[0] == 0);
  CHECK(m.total_in_flight == 0);
}

static void test_sentmeta_ring_full(void) {
  quic_sentmeta m;
  quic_sentmeta_init(&m);

  for (usz i = 0; i < QUIC_SENTMETA_CAP; i++)
    CHECK(quic_sentmeta_on_sent(&m, &(quic_sentmeta_out){i, 0, 1, 1, 1}) == 1);
  CHECK(
      quic_sentmeta_on_sent(&m, &(quic_sentmeta_out){9999, 0, 1, 1, 1}) ==
      0); /* full */
  CHECK(m.count == QUIC_SENTMETA_CAP);
}

static void test_sentmeta_send_ack_roundtrip(void) {
  quic_sentmeta       m;
  quic_sentmeta_acked out = {0, 0};
  quic_sentmeta_init(&m);

  quic_sentmeta_on_sent(&m, &(quic_sentmeta_out){1, 10, 1, 1, 1200});
  quic_sentmeta_on_sent(&m, &(quic_sentmeta_out){2, 20, 1, 1, 1200});
  CHECK(m.total_in_flight == 2400);

  quic_sentmeta_on_ack(&m, 1, &out);
  CHECK(m.total_in_flight == 1200); /* one packet's bytes drained */
  quic_sentmeta_on_ack(&m, 2, &out);
  CHECK(m.total_in_flight == 0);
}

void test_sentmeta(void) {
  test_sentmeta_on_sent_adds_inflight();
  test_sentmeta_on_sent_non_inflight_no_bytes();
  test_sentmeta_on_ack_subtracts_and_returns_time();
  test_sentmeta_on_ack_unknown_pn();
  test_sentmeta_loss_packet_threshold_boundary();
  test_sentmeta_loss_time_threshold_boundary();
  test_sentmeta_ring_full();
  test_sentmeta_send_ack_roundtrip();
}

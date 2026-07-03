#include "test.h"

/* Packet threshold: pn 3+ below largest_acked is reported lost and removed. */
static void test_lossdrive_packet_threshold(void) {
  quic_sentpkt t;
  quic_sentpkt_init(&t);
  quic_sentpkt_on_send(
      &t,
      &(quic_sentpkt_out){0, 100, 1, 1200}); /* gap 3 from acked 3 -> lost */
  quic_sentpkt_on_send(
      &t, &(quic_sentpkt_out){1, 100, 1, 1200}); /* gap 2 -> kept */
  quic_sentpkt_on_send(
      &t, &(quic_sentpkt_out){3, 200, 1, 1200}); /* the acked packet, kept */

  u64 lost[8];
  usz n = 0;
  quic_lossdrive_on_ack(
      &t, &(quic_lossdrive_in){3, 1000, 1000000}, (quic_u64out){lost, &n});

  CHECK(n == 1);
  CHECK(lost[0] == 0);
  /* pn 0 removed from the table; the two below-threshold stay. */
  CHECK(quic_sentpkt_count(&t) == 2);
}

/* Nothing past either threshold: no candidates, table untouched. */
static void test_lossdrive_none_lost(void) {
  quic_sentpkt t;
  quic_sentpkt_init(&t);
  quic_sentpkt_on_send(&t, &(quic_sentpkt_out){5, 100, 1, 1200});
  quic_sentpkt_on_send(&t, &(quic_sentpkt_out){6, 100, 1, 1200});

  u64 lost[8];
  usz n = 0;
  quic_lossdrive_on_ack(
      &t, &(quic_lossdrive_in){6, 200, 1000000}, (quic_u64out){lost, &n});

  CHECK(n == 0);
  CHECK(quic_sentpkt_count(&t) == 2);
}

void test_lossdrive(void) {
  test_lossdrive_packet_threshold();
  test_lossdrive_none_lost();
}

#include "test.h"

/* Single contiguous range: largest=5, first_range_len=2 acks 5,4,3. */
static void test_ack_process_first_range(void) {
  sentpkt t;
  sentpkt_init(&t);
  for (u64 pn = 1; pn <= 5; pn++)
    sentpkt_on_send(&t, &(sentpkt_out){pn, 0, 1, 1});
  u64 acked[8];
  usz n         = 99;
  u64 ranges[1] = {2}; /* first ack range length */
  ack_process(&t, &(ackset){5, ranges, 1}, (u64out){acked, &n});
  CHECK(n == 3);                 /* 5,4,3 removed */
  CHECK(sentpkt_count(&t) == 2); /* 1,2 remain */
}

/* Gap range: largest=10 first_len=0 (just 10), gap=1, len=1 acks 8,7. */
static void test_ack_process_gap(void) {
  sentpkt t;
  sentpkt_init(&t);
  for (u64 pn = 6; pn <= 10; pn++)
    sentpkt_on_send(&t, &(sentpkt_out){pn, 0, 1, 1});
  u64 acked[8];
  usz n         = 0;
  u64 ranges[3] = {0, 1, 1}; /* first_len=0, gap=1, range_len=1 */
  ack_process(&t, &(ackset){10, ranges, 3}, (u64out){acked, &n});
  /* acks 10, then skip 9, ack 8 and 7 */
  CHECK(n == 3);
  CHECK(sentpkt_count(&t) == 2); /* 6 and 9 remain */
}

/* Re-acking an already-removed packet does not report it twice. */
static void test_ack_process_idempotent(void) {
  sentpkt t;
  sentpkt_init(&t);
  sentpkt_on_send(&t, &(sentpkt_out){1, 0, 1, 1});
  u64 acked[4];
  usz n         = 0;
  u64 ranges[1] = {0};
  ack_process(&t, &(ackset){1, ranges, 1}, (u64out){acked, &n});
  CHECK(n == 1);
  n = 99;
  ack_process(&t, &(ackset){1, ranges, 1}, (u64out){acked, &n});
  CHECK(n == 0);
}

void test_ack_process(void) {
  test_ack_process_first_range();
  test_ack_process_gap();
  test_ack_process_idempotent();
}

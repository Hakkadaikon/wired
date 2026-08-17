#include "test.h"

/* Encode an ACK frame from explicit [hi,lo] ranges (descending). */
static usz build_ack(u8* buf, usz cap, const ack_range* r, usz n) {
  ack_frame f;
  f.ack_delay = 0;
  f.has_ecn   = 0;
  f.n_ranges  = n;
  for (usz i = 0; i < n; i++) f.ranges[i] = r[i];
  return ack_encode(buf, cap, &f);
}

/* RFC 9002 6 / RFC 9000 19.3: ACK frame range -> sent acked confirmation. */
void test_ackrange_process(void) {
  u8  buf[64];
  u64 acked[16];
  usz n;

  /* contiguous range 3..5 acks exactly those sent packets */
  {
    sentpkt t;
    sentpkt_init(&t);
    for (u64 pn = 1; pn <= 5; pn++)
      sentpkt_on_send(&t, &(sentpkt_out){pn, 0, 1, 1});
    ack_range r[1] = {{5, 3}};
    usz       len  = build_ack(buf, sizeof buf, r, 1);
    CHECK(len > 0);
    CHECK(
        ackrange_process(&t, wired_span_of(buf, len), (u64out){acked, &n}) ==
        1);
    CHECK(n == 3);                 /* 5,4,3 acked */
    CHECK(sentpkt_count(&t) == 2); /* 1,2 still in flight */
  }

  /* gap-separated ranges 7..8 and 3..4: 5,6 skipped, stay in flight */
  {
    sentpkt t;
    sentpkt_init(&t);
    for (u64 pn = 1; pn <= 8; pn++)
      sentpkt_on_send(&t, &(sentpkt_out){pn, 0, 1, 1});
    ack_range r[2] = {{8, 7}, {4, 3}};
    usz       len  = build_ack(buf, sizeof buf, r, 2);
    CHECK(len > 0);
    CHECK(
        ackrange_process(&t, wired_span_of(buf, len), (u64out){acked, &n}) ==
        1);
    CHECK(n == 4);                 /* 8,7,4,3 acked */
    CHECK(sentpkt_count(&t) == 4); /* 1,2,5,6 remain */
  }

  /* malformed frame: report failure, nothing acked */
  {
    sentpkt t;
    sentpkt_init(&t);
    sentpkt_on_send(&t, &(sentpkt_out){1, 0, 1, 1});
    u8 bad[2] = {0x02, 0x00};
    CHECK(
        ackrange_process(
            &t, wired_span_of(bad, sizeof bad), (u64out){acked, &n}) == 0);
    CHECK(n == 0);
    CHECK(sentpkt_count(&t) == 1);
  }
}

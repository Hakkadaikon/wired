#include "test.h"

static void test_sentpkt_init_empty(void) {
  sentpkt t;
  sentpkt_init(&t);
  CHECK(sentpkt_count(&t) == 0);
}

static void test_sentpkt_count_after_send(void) {
  sentpkt t;
  sentpkt_init(&t);
  CHECK(sentpkt_on_send(&t, &(sentpkt_out){1, 100, 1, 1200}) == 1);
  CHECK(sentpkt_on_send(&t, &(sentpkt_out){2, 200, 0, 40}) == 1);
  CHECK(sentpkt_count(&t) == 2);
}

/* Capacity boundary: the (CAP+1)th send is rejected and not counted. */
static void test_sentpkt_full(void) {
  sentpkt t;
  sentpkt_init(&t);
  for (u64 pn = 0; pn < SENTPKT_CAP; pn++)
    CHECK(sentpkt_on_send(&t, &(sentpkt_out){pn, 0, 1, 1}) == 1);
  CHECK(sentpkt_on_send(&t, &(sentpkt_out){SENTPKT_CAP, 0, 1, 1}) == 0);
  CHECK(sentpkt_count(&t) == SENTPKT_CAP);
}

void test_sentpkt(void) {
  test_sentpkt_init_empty();
  test_sentpkt_count_after_send();
  test_sentpkt_full();
}

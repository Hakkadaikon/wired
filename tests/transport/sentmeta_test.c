#include "test.h"

static void test_sentmeta_on_sent_adds_inflight(void) {
  sentmeta m;
  sentmeta_init(&m);

  CHECK(sentmeta_on_sent(&m, &(sentmeta_out){0, 100, 1, 1, 1200}) == 1);
  CHECK(m.count == 1);
  CHECK(m.total_in_flight == 1200);
}

static void test_sentmeta_on_sent_non_inflight_no_bytes(void) {
  sentmeta m;
  sentmeta_init(&m);

  /* ACK-only packet: ack_eliciting=0, in_flight=0 -> no bytes counted. */
  CHECK(sentmeta_on_sent(&m, &(sentmeta_out){5, 100, 0, 0, 40}) == 1);
  CHECK(m.count == 1);
  CHECK(m.total_in_flight == 0);
}

static void test_sentmeta_ring_full(void) {
  sentmeta m;
  sentmeta_init(&m);

  for (usz i = 0; i < SENTMETA_CAP; i++) {
    CHECK(sentmeta_on_sent(&m, &(sentmeta_out){i, 0, 1, 1, 1}) == 1);
  }
  CHECK(
      sentmeta_on_sent(&m, &(sentmeta_out){9999, 0, 1, 1, 1}) == 0); /* full */
  CHECK(m.count == SENTMETA_CAP);
}

/* sentmeta_uncount: the packet stays tracked but n of its bytes leave
 * total_in_flight, at most all of them; untracked pns change nothing. */
static void test_sentmeta_uncount(void) {
  sentmeta m;
  sentmeta_init(&m);
  sentmeta_on_sent(&m, &(sentmeta_out){1, 10, 1, 1, 1200});
  sentmeta_on_sent(&m, &(sentmeta_out){2, 20, 1, 1, 300});
  sentmeta_uncount(&m, 1, 1100);
  CHECK(m.total_in_flight == 400); /* 100 + 300 */
  sentmeta_uncount(&m, 1, 5000);   /* clamped at the 100 still counted */
  CHECK(m.total_in_flight == 300);
  sentmeta_uncount(&m, 9, 10);
  CHECK(m.total_in_flight == 300);
}

void test_sentmeta(void) {
  test_sentmeta_uncount();
  test_sentmeta_on_sent_adds_inflight();
  test_sentmeta_on_sent_non_inflight_no_bytes();
  test_sentmeta_ring_full();
}

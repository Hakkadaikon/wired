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

/* The live bitmap follows the used flags through sends and reclaims, in
 * every word, and sentmeta_next visits exactly the used slots in index
 * order -- also when the slot just visited is reclaimed. */
static void test_sentmeta_next_matches_used(void) {
  static sentmeta m;
  u32             rng = 0x736d6574;
  usz             n   = 0;
  sentmeta_init(&m);
  CHECK(sentmeta_next(&m, 0) == SENTMETA_CAP);
  for (usz i = 0; i < SENTMETA_CAP; i++) {
    sentmeta_out o = {i, 1, 1, 1, 10};
    CHECK(sentmeta_on_sent(&m, &o));
  }
  CHECK(sentmeta_next(&m, SENTMETA_CAP - 1) == SENTMETA_CAP - 1);
  CHECK(sentmeta_next(&m, SENTMETA_CAP) == SENTMETA_CAP);
  for (usz i = 0; i < SENTMETA_CAP; i++) { /* free a scattered half */
    rng = rng * 1664525u + 1013904223u;
    if (rng >> 31) {
      sentmeta_reclaim(&m, i);
    }
  }
  for (usz i = 0; i < SENTMETA_CAP && n == 0; i++) { /* the first free slot */
    if (!m.pkts[i].used) {
      CHECK(sentmeta_on_sent(&m, &(sentmeta_out){900, 1, 1, 1, 10}));
      CHECK(sentmeta_find(&m, 900) == i); /* is the next one handed out */
      n = 1;
    }
  }
  CHECK(n == 1);
  n = 0;
  for (usz i = 0; i < SENTMETA_CAP; i++) {
    CHECK((int)(m.live[i / 64] >> (i % 64) & 1) == m.pkts[i].used);
    n += (usz)m.pkts[i].used;
  }
  CHECK(n == m.count && n > 0 && n < SENTMETA_CAP);
  for (usz i = sentmeta_next(&m, 0), prev = 0; i < SENTMETA_CAP;
       i = sentmeta_next(&m, i + 1)) {
    CHECK(m.pkts[i].used && i >= prev);
    CHECK(sentmeta_find(&m, m.pkts[i].pn) == i);
    prev = i;
    sentmeta_reclaim(&m, i);
    n--;
  }
  CHECK(n == 0 && m.count == 0 && sentmeta_find(&m, 900) == SENTMETA_CAP);
}

void test_sentmeta(void) {
  test_sentmeta_next_matches_used();
  test_sentmeta_uncount();
  test_sentmeta_on_sent_adds_inflight();
  test_sentmeta_on_sent_non_inflight_no_bytes();
  test_sentmeta_ring_full();
}

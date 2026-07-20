#include "test.h"

/* RFC 8446 8.1 / RFC 9001 9.2: a server must reject 0-RTT for any ticket it
 * has already seen once -- this bounded, process-lifetime, single-process
 * tracker is the thing quic_zerortt_replay_ok's ticket_first_use argument
 * comes from. */

static quic_span zerortt_seen_span(const u8* p, usz n) {
  return quic_span_of(p, n);
}

/* A ticket identity never seen before is a first use. */
static void test_seen_fresh_is_first_use(void) {
  quic_zerortt_seen s;
  const u8          id[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  quic_zerortt_seen_init(&s);
  CHECK(quic_zerortt_seen_check(&s, zerortt_seen_span(id, sizeof id)) == 1);
}

/* The same identity presented a second time is a replay, not a first use. */
static void test_seen_replay_is_not_first_use(void) {
  quic_zerortt_seen s;
  const u8          id[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  quic_zerortt_seen_init(&s);
  CHECK(quic_zerortt_seen_check(&s, zerortt_seen_span(id, sizeof id)) == 1);
  CHECK(quic_zerortt_seen_check(&s, zerortt_seen_span(id, sizeof id)) == 0);
  CHECK(quic_zerortt_seen_check(&s, zerortt_seen_span(id, sizeof id)) == 0);
}

/* Two distinct identities are each their own first use, independently. */
static void test_seen_distinct_identities_independent(void) {
  quic_zerortt_seen s;
  const u8          a[4] = {0xaa, 0xaa, 0xaa, 0xaa};
  const u8          b[4] = {0xbb, 0xbb, 0xbb, 0xbb};
  quic_zerortt_seen_init(&s);
  CHECK(quic_zerortt_seen_check(&s, zerortt_seen_span(a, sizeof a)) == 1);
  CHECK(quic_zerortt_seen_check(&s, zerortt_seen_span(b, sizeof b)) == 1);
  CHECK(quic_zerortt_seen_check(&s, zerortt_seen_span(a, sizeof a)) == 0);
  CHECK(quic_zerortt_seen_check(&s, zerortt_seen_span(b, sizeof b)) == 0);
}

/* Once the fixed-capacity ring wraps, the oldest entry is evicted and its
 * identity is treated as a fresh first use again on re-presentation
 * (ponytail: bounded memory over perfect long-window replay detection --
 * acceptable since a ticket also expires on its own lifetime). */
static void test_seen_capacity_evicts_oldest(void) {
  quic_zerortt_seen s;
  u8                id[QUIC_ZERORTT_SEEN_CAP + 1][4];
  quic_zerortt_seen_init(&s);
  for (usz i = 0; i < QUIC_ZERORTT_SEEN_CAP + 1; i++) {
    id[i][0] = (u8)i;
    id[i][1] = (u8)(i >> 8);
    id[i][2] = 0xEE;
    id[i][3] = 0xEE;
    CHECK(quic_zerortt_seen_check(&s, zerortt_seen_span(id[i], 4)) == 1);
  }
  /* The very first identity was evicted to make room -- it is seen as fresh
   * again. */
  CHECK(quic_zerortt_seen_check(&s, zerortt_seen_span(id[0], 4)) == 1);
}

void test_zerortt_seen(void) {
  test_seen_fresh_is_first_use();
  test_seen_replay_is_not_first_use();
  test_seen_distinct_identities_independent();
  test_seen_capacity_evicts_oldest();
}

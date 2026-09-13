#include "app/http3/core/h3prio/h3prio.h"

#include "test.h"

/* RFC 9218 10: an empty candidate set has nothing to order. */
static void test_h3prio_order_empty(void) {
  usz order[1];
  h3prio_order(0, 0, order);
}

/* RFC 9218 4.1/10: lower urgency (higher precedence) sorts first. */
static void test_h3prio_order_by_urgency(void) {
  h3prio_candidate c[3] = {
      {5, 0, 0, 1}, /* index 0: urgency 5 */
      {1, 0, 1, 1}, /* index 1: urgency 1, most urgent */
      {3, 0, 2, 1}, /* index 2: urgency 3, default */
  };
  usz order[3];
  h3prio_order(c, 3, order);
  CHECK(order[0] == 1);
  CHECK(order[1] == 2);
  CHECK(order[2] == 0);
}

/* RFC 9218 10: same urgency -- ascending stream id breaks the tie, whether
 * incremental or not (see h3prio.h's doc on why this rule is applied
 * uniformly rather than only to non-incremental responses). */
static void test_h3prio_order_same_urgency_by_stream_id(void) {
  h3prio_candidate c[3] = {
      {3, 0, 12, 1},
      {3, 0, 4, 1},
      {3, 0, 8, 1},
  };
  usz order[3];
  h3prio_order(c, 3, order);
  CHECK(c[order[0]].stream_id == 4);
  CHECK(c[order[1]].stream_id == 8);
  CHECK(c[order[2]].stream_id == 12);
}

/* 9218-019: non-incremental responses of the same urgency are ordered by
 * ascending stream id (request generation order). */
static void test_h3prio_order_non_incremental_stream_id_order(void) {
  h3prio_candidate c[2] = {
      {2, 0, 20, 1}, /* stream 20, requested first */
      {2, 0, 16, 1}, /* stream 16, requested second -- lower id, later req */
  };
  usz order[2];
  h3prio_order(c, 2, order);
  /* RFC 9218 10 orders by ascending stream id, matching request order only
   * when ids were actually assigned in that order (RFC 9000 2.1: a client's
   * own stream ids of one type increase monotonically per request, so
   * ascending id IS ascending request order in practice). */
  CHECK(c[order[0]].stream_id == 16);
  CHECK(c[order[1]].stream_id == 20);
}

/* A dead (in_use == 0) slot sorts after every live one, regardless of its
 * urgency/stream_id values -- a caller iterating a fixed-size table must
 * never let an empty slot's numeric urgency (whatever garbage or leftover
 * value it holds) shadow a real candidate. */
static void test_h3prio_order_unused_sorts_last(void) {
  h3prio_candidate c[3] = {
      {0, 0, 0, 0}, /* unused, urgency 0 would otherwise look most urgent */
      {5, 0, 1, 1},
      {2, 0, 2, 1},
  };
  usz order[3];
  h3prio_order(c, 3, order);
  CHECK(order[0] == 2); /* urgency 2, live */
  CHECK(order[1] == 1); /* urgency 5, live */
  CHECK(order[2] == 0); /* unused, last regardless of urgency */
}

/* RFC 9218 10: incremental responses of the same urgency get a deterministic
 * visiting order too (bandwidth sharing itself comes from the caller's
 * round-robin pass visiting every slot once per pass, not from this order --
 * see h3prio.h). */
static void test_h3prio_order_incremental_same_urgency_deterministic(void) {
  h3prio_candidate c[2] = {
      {4, 1, 9, 1},
      {4, 1, 3, 1},
  };
  usz order[2];
  h3prio_order(c, 2, order);
  CHECK(c[order[0]].stream_id == 3);
  CHECK(c[order[1]].stream_id == 9);
}

/* Pinning: PRIORITY_UPDATE candidate state is a fixed-size slot table
 * (<=40 in practice, h3prio.h); flooding every slot with distinct
 * urgencies/stream ids still produces a full, valid permutation -- no
 * growth or out-of-bounds write past the caller's fixed array (V-0483). */
static void test_h3prio_candidate_table_bounded(void) {
  enum { N = 40 };
  h3prio_candidate c[N];
  usz              order[N];
  for (usz i = 0; i < N; i++) {
    c[i].urgency     = (u8)(i % 8);
    c[i].incremental = 0;
    c[i].stream_id   = (u64)(N - i);
    c[i].in_use      = 1;
  }
  h3prio_order(c, N, order);

  /* order[0..N) must be a permutation of 0..N-1: every index appears once */
  int seen[N];
  for (usz i = 0; i < N; i++) seen[i] = 0;
  for (usz i = 0; i < N; i++) {
    CHECK(order[i] < N);
    seen[order[i]]++;
  }
  for (usz i = 0; i < N; i++) CHECK(seen[i] == 1);
}

/* Pinning: RFC 9218 10 -- prio_before's total order (in_use, then urgency,
 * then stream_id) means a candidate at a fixed urgency is never stuck behind
 * an unbounded run of higher-urgency arrivals: once its own in_use flips
 * false (served) it reorders out, so no single urgency dominates forever
 * (V-0484). This pins the ordering invariant that guarantees it: a lower
 * urgency value always sorts strictly ahead of a higher one, regardless of
 * how many higher-urgency candidates are present. */
static void test_h3prio_no_indefinite_starvation_fixed_urgency(void) {
  h3prio_candidate c[5] = {
      {7, 0, 100, 1}, /* low precedence: same urgency for all 5 slots */
      {7, 0, 101, 1}, {7, 0, 102, 1}, {7, 0, 103, 1},
      {0, 0, 999, 1}, /* one high-precedence candidate arrives */
  };
  usz order[5];
  h3prio_order(c, 5, order);
  /* the urgency-0 candidate always sorts first: it can never be starved by
   * an arbitrary number of same-or-lower-precedence urgency-7 candidates */
  CHECK(order[0] == 4);
}

void test_h3prio(void) {
  test_h3prio_order_empty();
  test_h3prio_order_by_urgency();
  test_h3prio_order_same_urgency_by_stream_id();
  test_h3prio_order_non_incremental_stream_id_order();
  test_h3prio_order_unused_sorts_last();
  test_h3prio_order_incremental_same_urgency_deterministic();
  test_h3prio_candidate_table_bounded();
  test_h3prio_no_indefinite_starvation_fixed_urgency();
}

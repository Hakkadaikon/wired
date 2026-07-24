#include "test.h"

/* RFC 9221 5.1: urgency 0..7 valid, matching RFC 9218 4's range. */
static void test_dgpriority_valid(void) {
  CHECK(quic_dgpriority_valid(0) == 1);
  CHECK(quic_dgpriority_valid(QUIC_DGPRIORITY_MAX) == 1);
  CHECK(quic_dgpriority_valid(QUIC_DGPRIORITY_MAX + 1) == 0);
}

/* RFC 9221 5.1: lower urgency value outranks a higher one; equal urgencies
 * outrank neither way (same rule as quic_h3_priority_higher). */
static void test_dgpriority_higher(void) {
  CHECK(quic_dgpriority_higher(1, 3) == 1);
  CHECK(quic_dgpriority_higher(3, 1) == 0);
  CHECK(quic_dgpriority_higher(3, 3) == 0);
}

/* RFC 9221 5.1: among several DATAGRAM candidates, pick selects the most
 * urgent (lowest urgency) one. */
static void test_dgpriority_pick_selects_most_urgent(void) {
  quic_dgpriority_candidate c[3] = {
      {quic_span_of((const u8*)"low", 3), 5},
      {quic_span_of((const u8*)"high", 4), 1},
      {quic_span_of((const u8*)"mid", 3), 3},
  };
  CHECK(quic_dgpriority_pick(c, 3) == 1);
}

/* A tie in urgency keeps the earliest candidate (deterministic, stable
 * priority-then-arrival order). */
static void test_dgpriority_pick_tie_keeps_earliest(void) {
  quic_dgpriority_candidate c[2] = {
      {quic_span_of((const u8*)"first", 5), 3},
      {quic_span_of((const u8*)"second", 6), 3},
  };
  CHECK(quic_dgpriority_pick(c, 2) == 0);
}

/* An empty candidate list has nothing to pick. */
static void test_dgpriority_pick_empty(void) {
  CHECK(quic_dgpriority_pick(0, 0) == -1);
}

/* RFC 9221 5.1: a DATAGRAM's urgency compares directly against a stream's
 * urgency (e.g. quic_h3_priority.urgency) on the same 0..7 scale -- a
 * DATAGRAM with urgency 1 outranks a default-priority (3) stream. */
static void test_dgpriority_compares_against_stream_urgency(void) {
  const u8 datagram_urgency = 1;
  const u8 stream_urgency   = QUIC_DGPRIORITY_DEFAULT; /* same scale as h3 */
  CHECK(quic_dgpriority_higher(datagram_urgency, stream_urgency) == 1);
}

void test_dgpriority(void) {
  test_dgpriority_valid();
  test_dgpriority_higher();
  test_dgpriority_pick_selects_most_urgent();
  test_dgpriority_pick_tie_keeps_earliest();
  test_dgpriority_pick_empty();
  test_dgpriority_compares_against_stream_urgency();
}

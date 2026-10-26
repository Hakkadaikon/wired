#include "test.h"

/* RFC 9221 5.1: urgency 0..7 valid, matching RFC 9218 4's range. */
static void test_dgpriority_valid(void) {
  CHECK(dgpriority_valid(0) == 1);
  CHECK(dgpriority_valid(DGPRIORITY_MAX) == 1);
  CHECK(dgpriority_valid(DGPRIORITY_MAX + 1) == 0);
}

/* RFC 9221 5.1: lower urgency value outranks a higher one; equal urgencies
 * outrank neither way (same rule as h3_priority_higher). */
static void test_dgpriority_higher(void) {
  CHECK(dgpriority_higher(1, 3) == 1);
  CHECK(dgpriority_higher(3, 1) == 0);
  CHECK(dgpriority_higher(3, 3) == 0);
}

/* RFC 9221 5.1: a DATAGRAM's urgency compares directly against a stream's
 * urgency (e.g. h3_priority.urgency) on the same 0..7 scale -- a
 * DATAGRAM with urgency 1 outranks a default-priority (3) stream. */
static void test_dgpriority_compares_against_stream_urgency(void) {
  const u8 datagram_urgency = 1;
  const u8 stream_urgency   = DGPRIORITY_DEFAULT; /* same scale as h3 */
  CHECK(dgpriority_higher(datagram_urgency, stream_urgency) == 1);
}

void test_dgpriority(void) {
  test_dgpriority_valid();
  test_dgpriority_higher();
  test_dgpriority_compares_against_stream_urgency();
}

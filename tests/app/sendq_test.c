#include "app/http3/server/sendq/sendq.h"

#include "test.h"

/* Slicing a 2.5-chunk stream yields chunk, chunk, then the tail with fin;
 * offsets advance by chunk and the queue is drained afterward. */
static void test_sendq_slices_partial_tail(void) {
  u8                bytes[25];
  wired_sendq       q;
  wired_sendq_slice s;
  wired_sendq_init(&q, bytes, 25, 10);
  CHECK(wired_sendq_all_sent(&q) == 0);
  CHECK(wired_sendq_next(&q, &s) == 1);
  CHECK(s.offset == 0 && s.len == 10 && s.fin == 0);
  CHECK(wired_sendq_next(&q, &s) == 1);
  CHECK(s.offset == 10 && s.len == 10 && s.fin == 0);
  CHECK(wired_sendq_next(&q, &s) == 1);
  CHECK(s.offset == 20 && s.len == 5 && s.fin == 1);
  /* drained: no further slice, all sent */
  CHECK(wired_sendq_next(&q, &s) == 0);
  CHECK(wired_sendq_all_sent(&q) == 1);
}

/* A stream of exactly two chunks ends with a full-size fin slice. */
static void test_sendq_exact_multiple(void) {
  u8                bytes[20];
  wired_sendq       q;
  wired_sendq_slice s;
  wired_sendq_init(&q, bytes, 20, 10);
  CHECK(wired_sendq_next(&q, &s) == 1);
  CHECK(s.offset == 0 && s.len == 10 && s.fin == 0);
  CHECK(wired_sendq_next(&q, &s) == 1);
  CHECK(s.offset == 10 && s.len == 10 && s.fin == 1);
  CHECK(wired_sendq_next(&q, &s) == 0);
}

/* A stream shorter than one chunk is a single fin slice. */
static void test_sendq_single_slice(void) {
  u8                bytes[3];
  wired_sendq       q;
  wired_sendq_slice s;
  wired_sendq_init(&q, bytes, 3, 10);
  CHECK(wired_sendq_next(&q, &s) == 1);
  CHECK(s.offset == 0 && s.len == 3 && s.fin == 1);
  CHECK(wired_sendq_next(&q, &s) == 0);
}

/* An empty stream yields no slice and counts as already sent. */
static void test_sendq_empty(void) {
  wired_sendq       q;
  wired_sendq_slice s;
  wired_sendq_init(&q, (const u8*)"", 0, 10);
  CHECK(wired_sendq_next(&q, &s) == 0);
  CHECK(wired_sendq_all_sent(&q) == 1);
}

void test_sendq(void) {
  test_sendq_slices_partial_tail();
  test_sendq_exact_multiple();
  test_sendq_single_slice();
  test_sendq_empty();
}

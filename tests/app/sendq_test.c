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

/* Ring mode: a slice never crosses the wrap (capped there, not at chunk),
 * and slice bytes resolve at p + offset % cap; a linear queue resolves at
 * p + offset unchanged. */
static void test_sendq_ring_wrap(void) {
  u8                buf[10];
  wired_sendq       q;
  wired_sendq_slice sl;
  wired_sendq_init(&q, buf, 8, 4);
  wired_sendq_set_ring(&q, 10);
  CHECK(wired_sendq_next(&q, &sl) == 1);
  CHECK(sl.offset == 0 && sl.len == 4);
  CHECK(wired_sendq_slice_data(&q, &sl) == buf);
  CHECK(wired_sendq_next(&q, &sl) == 1);
  CHECK(sl.offset == 4 && sl.len == 4 && sl.fin == 1);
  q.len =
      14; /* the caller extended past the wrap: [8,14) = buf[8..10)+[0..4) */
  CHECK(wired_sendq_next(&q, &sl) == 1);
  CHECK(sl.offset == 8 && sl.len == 2); /* capped at the wrap */
  CHECK(wired_sendq_slice_data(&q, &sl) == buf + 8);
  CHECK(wired_sendq_next(&q, &sl) == 1);
  CHECK(sl.offset == 10 && sl.len == 4 && sl.fin == 1);
  CHECK(wired_sendq_slice_data(&q, &sl) == buf); /* wrapped to the front */
}

/* Pinning: GHSA-p7c7-7c47-pwch-class QPACK-dyntable-exhaustion DoS --
 * unsent response bytes are only ever sliced out of the caller's ALREADY
 * fixed-capacity backing storage (the srvbigbuf/srvloop pools); no matter
 * how large a chunk size is requested, wired_sendq never produces a slice
 * whose offset+len exceeds the buffer len it was initialized with, so this
 * queue cannot itself grow past the fixed pool behind it (V-0437). */
static void test_sendq_bounded_by_fixed_pool(void) {
  u8                bytes[100];
  wired_sendq       q;
  wired_sendq_slice s;
  usz               total = 0;
  /* a chunk size far larger than the backing buffer: still bounded to it. */
  wired_sendq_init(&q, bytes, sizeof bytes, 10000);
  CHECK(wired_sendq_next(&q, &s) == 1);
  CHECK(s.offset + s.len <= sizeof bytes);
  CHECK(s.fin == 1);
  total += s.len;
  CHECK(wired_sendq_next(&q, &s) == 0); /* fully drained, no further slice */
  CHECK(total == sizeof bytes);
}

void test_sendq(void) {
  test_sendq_slices_partial_tail();
  test_sendq_exact_multiple();
  test_sendq_single_slice();
  test_sendq_empty();
  test_sendq_ring_wrap();
  test_sendq_bounded_by_fixed_pool();
}

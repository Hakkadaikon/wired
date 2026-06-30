#include "test.h"

static void test_stream_read_contiguous(void) {
  quic_stream_read s;
  quic_stream_read_init(&s);
  u8 in[3] = {1, 2, 3};
  CHECK(quic_stream_read_push(&s, 0, in, 3) == 1);

  u8  out[8];
  usz n = 99;
  quic_stream_read_pull(&s, out, sizeof out, &n);
  CHECK(n == 3);
  CHECK(out[0] == 1 && out[1] == 2 && out[2] == 3);

  /* nothing left after consuming all */
  quic_stream_read_pull(&s, out, sizeof out, &n);
  CHECK(n == 0);
}

static void test_stream_read_stops_at_gap(void) {
  quic_stream_read s;
  quic_stream_read_init(&s);
  u8 a[2] = {10, 11};
  u8 b[2] = {20, 21};
  /* push [0,2) and [4,6): a gap at [2,4) blocks delivery past offset 2 */
  CHECK(quic_stream_read_push(&s, 0, a, 2) == 1);
  CHECK(quic_stream_read_push(&s, 4, b, 2) == 1);

  u8  out[8];
  usz n = 99;
  quic_stream_read_pull(&s, out, sizeof out, &n);
  CHECK(n == 2); /* only the prefix before the gap */
  CHECK(out[0] == 10 && out[1] == 11);
}

static void test_stream_read_fills_gap_then_continues(void) {
  quic_stream_read s;
  quic_stream_read_init(&s);
  u8 a[2]   = {10, 11};
  u8 b[2]   = {20, 21};
  u8 mid[2] = {12, 13};
  quic_stream_read_push(&s, 0, a, 2);
  quic_stream_read_push(&s, 4, b, 2);

  u8  out[8];
  usz n;
  quic_stream_read_pull(&s, out, sizeof out, &n);
  CHECK(n == 2);

  /* fill the gap [2,4): now [2,6) becomes contiguous and readable */
  CHECK(quic_stream_read_push(&s, 2, mid, 2) == 1);
  quic_stream_read_pull(&s, out, sizeof out, &n);
  CHECK(n == 4);
  CHECK(out[0] == 12 && out[1] == 13 && out[2] == 20 && out[3] == 21);
}

static void test_stream_read_respects_cap(void) {
  quic_stream_read s;
  quic_stream_read_init(&s);
  u8 in[4] = {1, 2, 3, 4};
  quic_stream_read_push(&s, 0, in, 4);

  u8  out[8];
  usz n;
  quic_stream_read_pull(&s, out, 2, &n); /* cap of 2 limits the pull */
  CHECK(n == 2);
  CHECK(out[0] == 1 && out[1] == 2);
  quic_stream_read_pull(&s, out, 8, &n);
  CHECK(n == 2);
  CHECK(out[0] == 3 && out[1] == 4);
}

void test_stream_read(void) {
  test_stream_read_contiguous();
  test_stream_read_stops_at_gap();
  test_stream_read_fills_gap_then_continues();
  test_stream_read_respects_cap();
}

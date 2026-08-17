#include "test.h"

static void test_stream_read_contiguous(void) {
  stream_read s;
  stream_read_init(&s);
  u8 in[3] = {1, 2, 3};
  CHECK(stream_read_push(&s, 0, wired_span_of(in, 3)) == 1);

  u8         out[8];
  wired_obuf ob = obuf_of(out, sizeof out);
  stream_read_pull(&s, &ob);
  CHECK(ob.len == 3);
  CHECK(out[0] == 1 && out[1] == 2 && out[2] == 3);

  /* nothing left after consuming all */
  stream_read_pull(&s, &ob);
  CHECK(ob.len == 0);
}

static void test_stream_read_stops_at_gap(void) {
  stream_read s;
  stream_read_init(&s);
  u8 a[2] = {10, 11};
  u8 b[2] = {20, 21};
  /* push [0,2) and [4,6): a gap at [2,4) blocks delivery past offset 2 */
  CHECK(stream_read_push(&s, 0, wired_span_of(a, 2)) == 1);
  CHECK(stream_read_push(&s, 4, wired_span_of(b, 2)) == 1);

  u8         out[8];
  wired_obuf ob = obuf_of(out, sizeof out);
  stream_read_pull(&s, &ob);
  CHECK(ob.len == 2); /* only the prefix before the gap */
  CHECK(out[0] == 10 && out[1] == 11);
}

static void test_stream_read_fills_gap_then_continues(void) {
  stream_read s;
  stream_read_init(&s);
  u8 a[2]   = {10, 11};
  u8 b[2]   = {20, 21};
  u8 mid[2] = {12, 13};
  stream_read_push(&s, 0, wired_span_of(a, 2));
  stream_read_push(&s, 4, wired_span_of(b, 2));

  u8         out[8];
  wired_obuf ob = obuf_of(out, sizeof out);
  stream_read_pull(&s, &ob);
  CHECK(ob.len == 2);

  /* fill the gap [2,4): now [2,6) becomes contiguous and readable */
  CHECK(stream_read_push(&s, 2, wired_span_of(mid, 2)) == 1);
  stream_read_pull(&s, &ob);
  CHECK(ob.len == 4);
  CHECK(out[0] == 12 && out[1] == 13 && out[2] == 20 && out[3] == 21);
}

static void test_stream_read_respects_cap(void) {
  stream_read s;
  stream_read_init(&s);
  u8 in[4] = {1, 2, 3, 4};
  stream_read_push(&s, 0, wired_span_of(in, 4));

  u8         out[8];
  wired_obuf small = obuf_of(out, 2); /* cap of 2 limits the pull */
  stream_read_pull(&s, &small);
  CHECK(small.len == 2);
  CHECK(out[0] == 1 && out[1] == 2);
  wired_obuf rest = obuf_of(out, 8);
  stream_read_pull(&s, &rest);
  CHECK(rest.len == 2);
  CHECK(out[0] == 3 && out[1] == 4);
}

void test_stream_read(void) {
  test_stream_read_contiguous();
  test_stream_read_stops_at_gap();
  test_stream_read_fills_gap_then_continues();
  test_stream_read_respects_cap();
}

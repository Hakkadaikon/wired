#include "test.h"

/* Quarter Stream ID is the request stream ID divided by four. */
static void test_quarter_from_stream(void) {
  CHECK(h3_quarter_stream_id(0) == 0);
  CHECK(h3_quarter_stream_id(4) == 1);
  CHECK(h3_quarter_stream_id(8) == 2);
}

/* Reversing a Quarter Stream ID multiplies by four. */
static void test_stream_from_quarter(void) {
  CHECK(h3_stream_from_quarter(0) == 0);
  CHECK(h3_stream_from_quarter(1) == 4);
  CHECK(h3_stream_from_quarter(2) == 8);
}

/* For request-stream IDs (multiples of four) the round trip is exact. */
static void test_quarter_roundtrip(void) {
  for (u64 q = 0; q < 1000; q++)
    CHECK(h3_quarter_stream_id(h3_stream_from_quarter(q)) == q);
}

void test_h3dgram(void) {
  test_quarter_from_stream();
  test_stream_from_quarter();
  test_quarter_roundtrip();
}

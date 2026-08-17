#include "test.h"

void test_stream_bounds(void) {
  u64 max = MAX_OFFSET - 1; /* 2^62-1 */

  /* exact boundary: sum equals the final-size limit */
  CHECK(stream_bounds_ok(0, max) == 1);
  CHECK(stream_bounds_ok(max, 0) == 1);
  CHECK(stream_bounds_ok(max / 2, max - max / 2) == 1);

  /* one past the limit */
  CHECK(stream_bounds_ok(0, max + 1) == 0);
  CHECK(stream_bounds_ok(max, 1) == 0);
  CHECK(stream_bounds_ok(1, max) == 0);

  /* operand already over the limit */
  CHECK(stream_bounds_ok(MAX_OFFSET, 0) == 0);

  /* sum that would wrap u64 must still be rejected */
  CHECK(stream_bounds_ok((u64)-1, (u64)-1) == 0);

  /* trivial in-range */
  CHECK(stream_bounds_ok(0, 0) == 1);
  CHECK(stream_bounds_ok(100, 200) == 1);
}

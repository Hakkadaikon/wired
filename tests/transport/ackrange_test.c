#include "test.h"

/* RFC 9000 19.3: build Largest + descending contiguous ranges from ascending
 * received packet numbers. */
void test_ackrange(void) {
  u64 largest, r[8];

  /* empty input: nothing to acknowledge */
  {
    quic_u64obuf out = {r, 8, 0};
    CHECK(quic_ackgen_build_ranges((quic_u64view){0, 0}, &largest, &out) == 0);
  }

  /* single contiguous block 3..7: largest 7, first range length 4, no gaps */
  {
    const u64    pns[] = {3, 4, 5, 6, 7};
    quic_u64obuf out   = {r, 8, 0};
    CHECK(
        quic_ackgen_build_ranges((quic_u64view){pns, 5}, &largest, &out) == 1);
    CHECK(largest == 7);
    CHECK(out.len == 1);
    CHECK(r[0] == 4); /* 5 packets -> length 4 */
  }

  /* lone packet: length 0 */
  {
    const u64    pns[] = {9};
    quic_u64obuf out   = {r, 8, 0};
    CHECK(
        quic_ackgen_build_ranges((quic_u64view){pns, 1}, &largest, &out) == 1);
    CHECK(largest == 9);
    CHECK(out.len == 1);
    CHECK(r[0] == 0);
  }

  /* two blocks 0..1 and 4..5: largest 5, first len 1, gap then len 1.
   * RFC 19.3.1 Gap = (smallest_of_higher - largest_of_lower) - 2
   *           = (4 - 1) - 2 = 1. */
  {
    const u64    pns[] = {0, 1, 4, 5};
    quic_u64obuf out   = {r, 8, 0};
    CHECK(
        quic_ackgen_build_ranges((quic_u64view){pns, 4}, &largest, &out) == 1);
    CHECK(largest == 5);
    CHECK(out.len == 3);
    CHECK(r[0] == 1); /* 4,5 -> length 1 */
    CHECK(r[1] == 1); /* gap */
    CHECK(r[2] == 1); /* 0,1 -> length 1 */
  }

  /* cap too small for the second block: fail rather than overflow */
  {
    const u64    pns[] = {0, 1, 4, 5};
    quic_u64obuf out   = {r, 2, 0};
    CHECK(
        quic_ackgen_build_ranges((quic_u64view){pns, 4}, &largest, &out) == 0);
  }
}

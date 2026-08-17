#include "test.h"

void test_odcid(void) {
  u8 dcid[8]   = {1, 2, 3, 4, 5, 6, 7, 8};
  u8 same[8]   = {1, 2, 3, 4, 5, 6, 7, 8};
  u8 diff[8]   = {1, 2, 3, 4, 5, 6, 7, 9};
  u8 shortc[4] = {1, 2, 3, 4};

  CHECK(tpverify_odcid(wired_span_of(dcid, 8), wired_span_of(same, 8)) == 1);
  CHECK(tpverify_odcid(wired_span_of(dcid, 8), wired_span_of(diff, 8)) == 0);
  CHECK(
      tpverify_odcid(wired_span_of(dcid, 8), wired_span_of(shortc, 4)) ==
      0); /* length mismatch */
  CHECK(
      tpverify_odcid(wired_span_of(dcid, 0), wired_span_of(same, 0)) ==
      1); /* zero-length CIDs */
}

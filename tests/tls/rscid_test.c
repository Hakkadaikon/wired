#include "test.h"

void test_rscid(void) {
  u8         rscid[6] = {1, 1, 2, 3, 5, 8};
  u8         same[6]  = {1, 1, 2, 3, 5, 8};
  u8         diff[6]  = {1, 1, 2, 3, 5, 9};
  wired_span r        = wired_span_of(rscid, 6);
  wired_span s        = wired_span_of(same, 6);
  wired_span d        = wired_span_of(diff, 6);
  wired_span none     = wired_span_of(0, 0);

  /* Retry occurred, parameter present and matching -> ok */
  CHECK(tpverify_rscid(&(tpverify_rscid_in){1, r, s, 1}) == 1);
  /* Retry occurred, parameter present but mismatching -> violation */
  CHECK(tpverify_rscid(&(tpverify_rscid_in){1, r, d, 1}) == 0);
  /* Retry occurred but parameter absent -> violation */
  CHECK(tpverify_rscid(&(tpverify_rscid_in){1, r, none, 0}) == 0);
  /* No Retry and parameter present -> violation */
  CHECK(tpverify_rscid(&(tpverify_rscid_in){0, none, s, 1}) == 0);
  /* No Retry and parameter absent -> ok */
  CHECK(tpverify_rscid(&(tpverify_rscid_in){0, none, none, 0}) == 1);
}

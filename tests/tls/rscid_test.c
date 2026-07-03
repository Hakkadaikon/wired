#include "test.h"

void test_rscid(void) {
  u8        rscid[6] = {1, 1, 2, 3, 5, 8};
  u8        same[6]  = {1, 1, 2, 3, 5, 8};
  u8        diff[6]  = {1, 1, 2, 3, 5, 9};
  quic_span r        = quic_span_of(rscid, 6);
  quic_span s        = quic_span_of(same, 6);
  quic_span d        = quic_span_of(diff, 6);
  quic_span none     = quic_span_of(0, 0);

  /* Retry occurred, parameter present and matching -> ok */
  CHECK(quic_tpverify_rscid(&(quic_tpverify_rscid_in){1, r, s, 1}) == 1);
  /* Retry occurred, parameter present but mismatching -> violation */
  CHECK(quic_tpverify_rscid(&(quic_tpverify_rscid_in){1, r, d, 1}) == 0);
  /* Retry occurred but parameter absent -> violation */
  CHECK(quic_tpverify_rscid(&(quic_tpverify_rscid_in){1, r, none, 0}) == 0);
  /* No Retry and parameter present -> violation */
  CHECK(quic_tpverify_rscid(&(quic_tpverify_rscid_in){0, none, s, 1}) == 0);
  /* No Retry and parameter absent -> ok */
  CHECK(quic_tpverify_rscid(&(quic_tpverify_rscid_in){0, none, none, 0}) == 1);
}

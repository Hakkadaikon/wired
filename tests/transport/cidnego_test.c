#include "test.h"

/* Peer SCID is adopted verbatim as our DCID. */
static void test_cidnego_adopt(void) {
  u8        scid[5] = {1, 2, 3, 4, 5};
  u8        dcid[20];
  quic_obuf ob = quic_obuf_of(dcid, sizeof(dcid));
  CHECK(quic_cidnego_peer_dcid(quic_span_of(scid, 5), &ob) == 1);
  CHECK(ob.len == 5);
  CHECK(quic_cidnego_match(quic_span_of(dcid, ob.len), quic_span_of(scid, 5)) == 1);
}

/* A zero-length connection ID is valid and round-trips. */
static void test_cidnego_zero_len(void) {
  u8        dcid[20];
  quic_obuf ob = quic_obuf_of(dcid, sizeof(dcid));
  CHECK(quic_cidnego_peer_dcid(quic_span_of((const u8 *)0, 0), &ob) == 1);
  CHECK(ob.len == 0);
  CHECK(quic_cidnego_match(quic_span_of(dcid, 0), quic_span_of(dcid, 0)) == 1);
}

/* The maximum 20-byte CID is accepted; 21 is rejected. */
static void test_cidnego_len_bounds(void) {
  u8        scid[21] = {0};
  u8        dcid[20];
  quic_obuf ob = quic_obuf_of(dcid, sizeof(dcid));
  CHECK(
      quic_cidnego_peer_dcid(quic_span_of(scid, 20), &ob) == 1 &&
      ob.len == 20);
  CHECK(quic_cidnego_peer_dcid(quic_span_of(scid, 21), &ob) == 0);
}

/* match distinguishes different lengths and differing bytes. */
static void test_cidnego_match_neg(void) {
  u8 a[3] = {1, 2, 3};
  u8 b[3] = {1, 2, 4};
  CHECK(quic_cidnego_match(quic_span_of(a, 3), quic_span_of(b, 3)) == 0); /* last byte differs */
  CHECK(quic_cidnego_match(quic_span_of(a, 3), quic_span_of(a, 2)) == 0); /* length differs */
  CHECK(quic_cidnego_match(quic_span_of(a, 2), quic_span_of(a, 2)) == 1);
}

void test_cidnego(void) {
  test_cidnego_adopt();
  test_cidnego_zero_len();
  test_cidnego_len_bounds();
  test_cidnego_match_neg();
}

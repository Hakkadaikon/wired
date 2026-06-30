#include "test.h"

/* Peer SCID is adopted verbatim as our DCID. */
static void test_cidnego_adopt(void) {
  u8  scid[5] = {1, 2, 3, 4, 5};
  u8  dcid[20];
  usz dlen = 99;
  CHECK(quic_cidnego_peer_dcid(scid, 5, dcid, &dlen) == 1);
  CHECK(dlen == 5);
  CHECK(quic_cidnego_match(dcid, dlen, scid, 5) == 1);
}

/* A zero-length connection ID is valid and round-trips. */
static void test_cidnego_zero_len(void) {
  u8  dcid[20];
  usz dlen = 99;
  CHECK(quic_cidnego_peer_dcid((const u8 *)0, 0, dcid, &dlen) == 1);
  CHECK(dlen == 0);
  CHECK(quic_cidnego_match(dcid, 0, dcid, 0) == 1);
}

/* The maximum 20-byte CID is accepted; 21 is rejected. */
static void test_cidnego_len_bounds(void) {
  u8  scid[21] = {0};
  u8  dcid[20];
  usz dlen;
  CHECK(quic_cidnego_peer_dcid(scid, 20, dcid, &dlen) == 1 && dlen == 20);
  CHECK(quic_cidnego_peer_dcid(scid, 21, dcid, &dlen) == 0);
}

/* match distinguishes different lengths and differing bytes. */
static void test_cidnego_match_neg(void) {
  u8 a[3] = {1, 2, 3};
  u8 b[3] = {1, 2, 4};
  CHECK(quic_cidnego_match(a, 3, b, 3) == 0); /* last byte differs */
  CHECK(quic_cidnego_match(a, 3, a, 2) == 0); /* length differs */
  CHECK(quic_cidnego_match(a, 2, a, 2) == 1);
}

void test_cidnego(void) {
  test_cidnego_adopt();
  test_cidnego_zero_len();
  test_cidnego_len_bounds();
  test_cidnego_match_neg();
}

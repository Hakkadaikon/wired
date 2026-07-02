#include "app/qpack/qpack/fieldline.h"

#include "test.h"

/* RFC 9204 4.5.2: static index 17 is 1Tiiiiii = 11010001 = 0xD1. */
static void test_fieldline_indexed_golden(void) {
  u8  buf[4];
  usz w = quic_qpack_indexed_encode(quic_mspan_of(buf, sizeof(buf)), 17, 1);
  CHECK(w == 1 && buf[0] == 0xD1);

  u64 idx;
  int st;
  usz r = quic_qpack_indexed_decode(quic_span_of(buf, w), &idx, &st);
  CHECK(r == w && idx == 17 && st == 1);
}

/* RFC 9204 4.5.2: index 63 fills the 6-bit prefix, spilling to 0xFF 0x00. */
static void test_fieldline_indexed_prefix_boundary(void) {
  u8  buf[4];
  usz w = quic_qpack_indexed_encode(quic_mspan_of(buf, sizeof(buf)), 63, 1);
  CHECK(w == 2 && buf[0] == 0xFF && buf[1] == 0x00);

  u64 idx;
  int st;
  usz r = quic_qpack_indexed_decode(quic_span_of(buf, w), &idx, &st);
  CHECK(r == w && idx == 63 && st == 1);
}

/* The dynamic-table form (T=0) clears bit 6 and still round-trips. */
static void test_fieldline_indexed_dynamic(void) {
  u8  buf[4];
  usz w = quic_qpack_indexed_encode(quic_mspan_of(buf, sizeof(buf)), 5, 0);
  CHECK(w == 1 && buf[0] == 0x85);

  u64 idx;
  int st;
  usz r = quic_qpack_indexed_decode(quic_span_of(buf, w), &idx, &st);
  CHECK(r == w && idx == 5 && st == 0);
}

/* A first byte without bit 7 is not an indexed field line. */
static void test_fieldline_indexed_reject(void) {
  u8  bad = 0x40;
  u64 idx;
  int st;
  CHECK(quic_qpack_indexed_decode(quic_span_of(&bad, 1), &idx, &st) == 0);
  CHECK(quic_qpack_indexed_decode(quic_span_of(&bad, 0), &idx, &st) == 0);
}

void test_fieldline(void) {
  test_fieldline_indexed_golden();
  test_fieldline_indexed_prefix_boundary();
  test_fieldline_indexed_dynamic();
  test_fieldline_indexed_reject();
}

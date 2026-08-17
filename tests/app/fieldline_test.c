#include "app/qpack/qpack/fieldline.h"

#include "test.h"

/* RFC 9204 4.5.2: static index 17 is 1Tiiiiii = 11010001 = 0xD1. */
static void test_fieldline_indexed_golden(void) {
  u8  buf[4];
  usz w = quic_qpack_indexed_encode(wired_mspan_of(buf, sizeof(buf)), 17, 1);
  CHECK(w == 1 && buf[0] == 0xD1);

  u64 idx;
  int st;
  usz r = quic_qpack_indexed_decode(wired_span_of(buf, w), &idx, &st);
  CHECK(r == w && idx == 17 && st == 1);
}

/* RFC 9204 4.5.2: index 63 fills the 6-bit prefix, spilling to 0xFF 0x00. */
static void test_fieldline_indexed_prefix_boundary(void) {
  u8  buf[4];
  usz w = quic_qpack_indexed_encode(wired_mspan_of(buf, sizeof(buf)), 63, 1);
  CHECK(w == 2 && buf[0] == 0xFF && buf[1] == 0x00);

  u64 idx;
  int st;
  usz r = quic_qpack_indexed_decode(wired_span_of(buf, w), &idx, &st);
  CHECK(r == w && idx == 63 && st == 1);
}

/* The dynamic-table form (T=0) clears bit 6 and still round-trips. */
static void test_fieldline_indexed_dynamic(void) {
  u8  buf[4];
  usz w = quic_qpack_indexed_encode(wired_mspan_of(buf, sizeof(buf)), 5, 0);
  CHECK(w == 1 && buf[0] == 0x85);

  u64 idx;
  int st;
  usz r = quic_qpack_indexed_decode(wired_span_of(buf, w), &idx, &st);
  CHECK(r == w && idx == 5 && st == 0);
}

/* A first byte without bit 7 is not an indexed field line. */
static void test_fieldline_indexed_reject(void) {
  u8  bad = 0x40;
  u64 idx;
  int st;
  CHECK(quic_qpack_indexed_decode(wired_span_of(&bad, 1), &idx, &st) == 0);
  CHECK(quic_qpack_indexed_decode(wired_span_of(&bad, 0), &idx, &st) == 0);
}

/* RFC 9204 Appendix B.2: 0x10 is Post-Base Index 0
 * (Absolute Index = Base(0) + Index(0)). */
static void test_fieldline_postbase_golden(void) {
  u8  buf[4];
  usz w =
      quic_qpack_indexed_postbase_encode(wired_mspan_of(buf, sizeof(buf)), 0);
  CHECK(w == 1 && buf[0] == 0x10);

  u64 pb;
  usz r = quic_qpack_indexed_postbase_decode(wired_span_of(buf, w), &pb);
  CHECK(r == w && pb == 0);
}

/* RFC 9204 Appendix B.2: 0x11 is Post-Base Index 1
 * (Absolute Index = Base(0) + Index(1)). */
static void test_fieldline_postbase_index_one(void) {
  u8  buf[4];
  usz w =
      quic_qpack_indexed_postbase_encode(wired_mspan_of(buf, sizeof(buf)), 1);
  CHECK(w == 1 && buf[0] == 0x11);

  u64 pb;
  usz r = quic_qpack_indexed_postbase_decode(wired_span_of(buf, w), &pb);
  CHECK(r == w && pb == 1);
}

/* Index 15 fills the 4-bit prefix, spilling to a continuation byte. */
static void test_fieldline_postbase_prefix_boundary(void) {
  u8  buf[4];
  usz w =
      quic_qpack_indexed_postbase_encode(wired_mspan_of(buf, sizeof(buf)), 15);
  CHECK(w == 2 && buf[0] == 0x1F && buf[1] == 0x00);

  u64 pb;
  usz r = quic_qpack_indexed_postbase_decode(wired_span_of(buf, w), &pb);
  CHECK(r == w && pb == 15);
}

/* Neither an Indexed Field Line (bit 7 set) nor an unrelated pattern is a
 * post-Base indexed field line. */
static void test_fieldline_postbase_reject(void) {
  u8  indexed = 0xD1; /* 1Tiiiiii, a plain Indexed Field Line */
  u8  litname = 0x21; /* 001NHiii, a Literal Field Line With Literal Name */
  u64 pb;
  CHECK(
      quic_qpack_indexed_postbase_decode(wired_span_of(&indexed, 1), &pb) == 0);
  CHECK(
      quic_qpack_indexed_postbase_decode(wired_span_of(&litname, 1), &pb) == 0);
  CHECK(
      quic_qpack_indexed_postbase_decode(wired_span_of(&indexed, 0), &pb) == 0);
}

void test_fieldline(void) {
  test_fieldline_indexed_golden();
  test_fieldline_indexed_prefix_boundary();
  test_fieldline_indexed_dynamic();
  test_fieldline_indexed_reject();
  test_fieldline_postbase_golden();
  test_fieldline_postbase_index_one();
  test_fieldline_postbase_prefix_boundary();
  test_fieldline_postbase_reject();
}

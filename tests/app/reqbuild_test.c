#include "test.h"

/* RFC 9114 4.1: HEADERS frame followed by a DATA frame. */
static void test_reqbuild_headers_data(void) {
  u8        h[] = {0xaa, 0xbb};
  u8        b[] = {0x01, 0x02, 0x03};
  u8        out[32];
  quic_obuf ob = {out, sizeof out, 0};
  CHECK(
      quic_h3req_build(
          quic_span_of(h, sizeof h), quic_span_of(b, sizeof b), &ob) == 1);
  /* HEADERS: type 0x01, len 2, payload; DATA: type 0x00, len 3, payload. */
  CHECK(ob.len == 2 + 2 + 2 + 3);
  CHECK(out[0] == 0x01 && out[1] == 2 && out[2] == 0xaa && out[3] == 0xbb);
  CHECK(out[4] == 0x00 && out[5] == 3 && out[6] == 0x01);
}

/* An empty body emits the HEADERS frame only. */
static void test_reqbuild_no_body(void) {
  u8        h[] = {0xaa, 0xbb};
  u8        out[32];
  quic_obuf ob = {out, sizeof out, 0};
  CHECK(
      quic_h3req_build(quic_span_of(h, sizeof h), quic_span_of(0, 0), &ob) ==
      1);
  CHECK(ob.len == 2 + 2);
  CHECK(out[0] == 0x01 && out[1] == 2);
}

/* Insufficient capacity fails without writing past the buffer. */
static void test_reqbuild_overflow(void) {
  u8        h[] = {0xaa, 0xbb};
  u8        b[] = {0x01, 0x02, 0x03};
  u8        out[5];
  quic_obuf ob = {out, sizeof out, 0};
  CHECK(
      quic_h3req_build(
          quic_span_of(h, sizeof h), quic_span_of(b, sizeof b), &ob) == 0);
}

void test_reqbuild(void) {
  test_reqbuild_headers_data();
  test_reqbuild_no_body();
  test_reqbuild_overflow();
}

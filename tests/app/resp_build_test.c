#include "test.h"

/* RFC 9114 4.1: HEADERS(:status field section) followed by DATA(body), and the
 * round trip back through the response parser recovers :status 200 and body. */
static void test_resp_build_roundtrip(void) {
  u8              b[] = {'h', 'i'};
  u8              out[32];
  quic_obuf       ob        = {out, sizeof out, 0};
  quic_h3req_resp resp      = {0};
  u64             idx       = 0;
  int             is_static = 0;
  CHECK(quic_h3resp_build(200, quic_span_of(b, sizeof b), &ob) == 1);
  CHECK(quic_h3req_resp_parse(quic_span_of(out, ob.len), &resp) == 1);
  /* field section: 2-byte prefix then Indexed Field Line for :status 200. */
  CHECK(
      resp.headers.n == 3 && resp.headers.p[0] == 0x00 &&
      resp.headers.p[1] == 0x00);
  CHECK(
      quic_qpack_indexed_decode(
          quic_span_of(resp.headers.p + 2, resp.headers.n - 2), &idx,
          &is_static) != 0);
  CHECK(is_static == 1 && idx == 25);
  CHECK(resp.body.n == 2 && resp.body.p[0] == 'h' && resp.body.p[1] == 'i');
}

/* An empty body emits the HEADERS frame only. */
static void test_resp_build_no_body(void) {
  u8              out[32];
  quic_obuf       ob   = {out, sizeof out, 0};
  quic_h3req_resp resp = {0};
  CHECK(quic_h3resp_build(200, quic_span_of(0, 0), &ob) == 1);
  CHECK(quic_h3req_resp_parse(quic_span_of(out, ob.len), &resp) == 1);
  CHECK(resp.headers.n == 3 && resp.body.p == 0 && resp.body.n == 0);
}

/* Insufficient capacity fails without writing past the buffer. */
static void test_resp_build_overflow(void) {
  u8        b[] = {'h', 'i'};
  u8        out[4];
  quic_obuf ob = {out, sizeof out, 0};
  CHECK(quic_h3resp_build(200, quic_span_of(b, sizeof b), &ob) == 0);
}

void test_resp_build(void) {
  test_resp_build_roundtrip();
  test_resp_build_no_body();
  test_resp_build_overflow();
}

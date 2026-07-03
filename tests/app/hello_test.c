#include "test.h"

/* RFC 9114 4.1: the hello response is status 200 with body "hello\n", and the
 * round trip recovers both. */
static void test_hello_roundtrip(void) {
  u8              out[32];
  quic_obuf       ob        = {out, sizeof out, 0};
  quic_h3req_resp resp      = {0};
  u64             idx       = 0;
  int             is_static = 0;
  CHECK(quic_h3resp_hello(&ob) == 1);
  CHECK(quic_h3req_resp_parse(quic_span_of(out, ob.len), &resp) == 1);
  CHECK(resp.headers.n == 3 && resp.headers.p[0] == 0x00 && resp.headers.p[1] == 0x00);
  CHECK(
      quic_qpack_indexed_decode(
          quic_span_of(resp.headers.p + 2, resp.headers.n - 2), &idx,
          &is_static) != 0);
  CHECK(is_static == 1 && idx == 25);
  CHECK(resp.body.n == 6);
  CHECK(resp.body.p[0] == 'h' && resp.body.p[4] == 'o' && resp.body.p[5] == '\n');
}

void test_hello(void) { test_hello_roundtrip(); }

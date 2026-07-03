#include "test.h"

/* RFC 9114 4.1: separate the leading HEADERS frame from the DATA frame. */
static void test_respparse_headers_data(void) {
  /* HEADERS(len2) {0xaa,0xbb}  DATA(len3) {1,2,3} */
  u8              stream[] = {0x01, 2, 0xaa, 0xbb, 0x00, 3, 1, 2, 3};
  quic_h3req_resp resp     = {0};
  CHECK(quic_h3req_resp_parse(quic_span_of(stream, sizeof stream), &resp) == 1);
  CHECK(resp.headers.n == 2 && resp.headers.p[0] == 0xaa && resp.headers.p[1] == 0xbb);
  CHECK(resp.body.n == 3 && resp.body.p[0] == 1 && resp.body.p[2] == 3);
}

/* A response with no DATA frame yields an empty body. */
static void test_respparse_no_body(void) {
  u8              stream[] = {0x01, 2, 0xaa, 0xbb};
  quic_h3req_resp resp     = {0};
  CHECK(quic_h3req_resp_parse(quic_span_of(stream, sizeof stream), &resp) == 1);
  CHECK(resp.headers.n == 2 && resp.body.p == 0 && resp.body.n == 0);
}

/* A stream not beginning with HEADERS is rejected. */
static void test_respparse_not_headers(void) {
  u8              stream[] = {0x00, 2, 0xaa, 0xbb};
  quic_h3req_resp resp     = {0};
  CHECK(quic_h3req_resp_parse(quic_span_of(stream, sizeof stream), &resp) == 0);
}

void test_respparse(void) {
  test_respparse_headers_data();
  test_respparse_no_body();
  test_respparse_not_headers();
}

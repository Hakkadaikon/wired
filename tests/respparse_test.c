#include "test.h"

/* RFC 9114 4.1: separate the leading HEADERS frame from the DATA frame. */
static void test_respparse_headers_data(void)
{
    /* HEADERS(len2) {0xaa,0xbb}  DATA(len3) {1,2,3} */
    u8 stream[] = {0x01, 2, 0xaa, 0xbb, 0x00, 3, 1, 2, 3};
    const u8 *h, *b;
    usz hl = 0, bl = 0;
    CHECK(quic_h3req_resp_parse(stream, sizeof stream, &h, &hl, &b, &bl) == 1);
    CHECK(hl == 2 && h[0] == 0xaa && h[1] == 0xbb);
    CHECK(bl == 3 && b[0] == 1 && b[2] == 3);
}

/* A response with no DATA frame yields an empty body. */
static void test_respparse_no_body(void)
{
    u8 stream[] = {0x01, 2, 0xaa, 0xbb};
    const u8 *h, *b;
    usz hl = 0, bl = 0;
    CHECK(quic_h3req_resp_parse(stream, sizeof stream, &h, &hl, &b, &bl) == 1);
    CHECK(hl == 2 && b == 0 && bl == 0);
}

/* A stream not beginning with HEADERS is rejected. */
static void test_respparse_not_headers(void)
{
    u8 stream[] = {0x00, 2, 0xaa, 0xbb};
    const u8 *h, *b;
    usz hl = 0, bl = 0;
    CHECK(quic_h3req_resp_parse(stream, sizeof stream, &h, &hl, &b, &bl) == 0);
}

void test_respparse(void)
{
    test_respparse_headers_data();
    test_respparse_no_body();
    test_respparse_not_headers();
}

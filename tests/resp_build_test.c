#include "test.h"

/* RFC 9114 4.1: HEADERS(:status field section) followed by DATA(body), and the
 * round trip back through the response parser recovers :status 200 and body. */
static void test_resp_build_roundtrip(void)
{
    u8 b[] = {'h', 'i'};
    u8 out[32];
    usz n = 0;
    const u8 *h, *body;
    usz hl = 0, bl = 0;
    u64 idx = 0;
    int is_static = 0;
    CHECK(quic_h3resp_build(200, b, sizeof b, out, sizeof out, &n) == 1);
    CHECK(quic_h3req_resp_parse(out, n, &h, &hl, &body, &bl) == 1);
    /* field section: 2-byte prefix then Indexed Field Line for :status 200. */
    CHECK(hl == 3 && h[0] == 0x00 && h[1] == 0x00);
    CHECK(quic_qpack_indexed_decode(h + 2, hl - 2, &idx, &is_static) != 0);
    CHECK(is_static == 1 && idx == 25);
    CHECK(bl == 2 && body[0] == 'h' && body[1] == 'i');
}

/* body_len 0 emits the HEADERS frame only. */
static void test_resp_build_no_body(void)
{
    u8 out[32];
    usz n = 0;
    const u8 *h, *body;
    usz hl = 0, bl = 0;
    CHECK(quic_h3resp_build(200, 0, 0, out, sizeof out, &n) == 1);
    CHECK(quic_h3req_resp_parse(out, n, &h, &hl, &body, &bl) == 1);
    CHECK(hl == 3 && body == 0 && bl == 0);
}

/* Insufficient capacity fails without writing past the buffer. */
static void test_resp_build_overflow(void)
{
    u8 b[] = {'h', 'i'};
    u8 out[4];
    usz n = 0;
    CHECK(quic_h3resp_build(200, b, sizeof b, out, sizeof out, &n) == 0);
}

void test_resp_build(void)
{
    test_resp_build_roundtrip();
    test_resp_build_no_body();
    test_resp_build_overflow();
}

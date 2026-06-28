#include "test.h"

/* RFC 9114 4.1: the hello response is status 200 with body "hello\n", and the
 * round trip recovers both. */
static void test_hello_roundtrip(void)
{
    u8 out[32];
    usz n = 0;
    const u8 *h, *body;
    usz hl = 0, bl = 0;
    u64 idx = 0;
    int is_static = 0;
    CHECK(quic_h3resp_hello(out, sizeof out, &n) == 1);
    CHECK(quic_h3req_resp_parse(out, n, &h, &hl, &body, &bl) == 1);
    CHECK(hl == 3 && h[0] == 0x00 && h[1] == 0x00);
    CHECK(quic_qpack_indexed_decode(h + 2, hl - 2, &idx, &is_static) != 0);
    CHECK(is_static == 1 && idx == 25);
    CHECK(bl == 6);
    CHECK(body[0] == 'h' && body[4] == 'o' && body[5] == '\n');
}

void test_hello(void)
{
    test_hello_roundtrip();
}

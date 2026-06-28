#include "test.h"

/* RFC 9204 4.5.6: an ordinary header encodes as a Literal Field Line With
 * Literal Name; decoding it back yields the same name and value. */
static void test_header_roundtrip(void)
{
    u8 out[64];
    usz n = 0;
    const u8 *name = (const u8 *)"user-agent";
    const u8 *value = (const u8 *)"quic/1";
    int never = 1;
    u8 nm[32], val[32];
    usz nlen = 0, vlen = 0, used;
    CHECK(quic_h3req_enc_header(name, 10, value, 6, out, sizeof out, &n) == 1);
    /* 001NHiii literal-name pattern, N=0, H=0. */
    CHECK((out[0] & 0xe0) == 0x20);
    used = quic_qpack_literal_name_decode(out, n, &never, nm, sizeof nm, &nlen,
                                          val, sizeof val, &vlen);
    CHECK(used == n && never == 0);
    CHECK(nlen == 10 && nm[0] == 'u' && nm[9] == 't');
    CHECK(vlen == 6 && val[0] == 'q' && val[5] == '1');
}

/* Insufficient capacity fails. */
static void test_header_overflow(void)
{
    u8 out[2];
    usz n = 0;
    const u8 *name = (const u8 *)"user-agent";
    const u8 *value = (const u8 *)"quic/1";
    CHECK(quic_h3req_enc_header(name, 10, value, 6, out, sizeof out, &n) == 0);
}

void test_header_encode(void)
{
    test_header_roundtrip();
    test_header_overflow();
}

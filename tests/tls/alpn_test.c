#include "test.h"

static void test_alpn_h3_roundtrip(void)
{
    const u8 h3[] = {0x68, 0x33};
    u8 buf[16];
    const u8 *out;
    usz olen;
    usz w = quic_tls_alpn_encode(buf, sizeof(buf), h3, sizeof(h3));
    usz r = quic_tls_alpn_decode_first(buf, w, &out, &olen);
    CHECK(w == 5 && r == w);
    CHECK(olen == 2 && out == buf + 3);
    CHECK(out[0] == 0x68 && out[1] == 0x33);
    /* wire: list length 0x0003, name length 0x02 */
    CHECK(buf[0] == 0x00 && buf[1] == 0x03 && buf[2] == 0x02);
}

static void test_alpn_truncated(void)
{
    const u8 h3[] = {0x68, 0x33};
    u8 buf[16];
    const u8 *out;
    usz olen;
    usz w = quic_tls_alpn_encode(buf, sizeof(buf), h3, sizeof(h3));
    /* list length claims 3 but only 2 readable past header */
    CHECK(quic_tls_alpn_decode_first(buf, w - 1, &out, &olen) == 0);
    CHECK(quic_tls_alpn_decode_first(buf, 2, &out, &olen) == 0);
}

static void test_alpn_bad_name_len(void)
{
    /* list length 3 but name length 5 overruns the list */
    u8 buf[8] = {0x00, 0x03, 0x05, 0x68, 0x33};
    const u8 *out;
    usz olen;
    CHECK(quic_tls_alpn_decode_first(buf, 5, &out, &olen) == 0);
}

static void test_alpn_encode_guard(void)
{
    const u8 h3[] = {0x68, 0x33};
    u8 buf[4];
    CHECK(quic_tls_alpn_encode(buf, sizeof(buf), h3, sizeof(h3)) == 0);
    CHECK(quic_tls_alpn_encode(buf, sizeof(buf), h3, 0) == 0);
}

void test_alpn(void)
{
    test_alpn_h3_roundtrip();
    test_alpn_truncated();
    test_alpn_bad_name_len();
    test_alpn_encode_guard();
}

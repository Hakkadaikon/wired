#include "test.h"

static void test_tpext_roundtrip(void)
{
    u8 tp[] = {0x00, 0x08, 0x12, 0x34};
    u8 buf[32];
    const u8 *out;
    usz olen;
    usz w = quic_tpext_encode(buf, sizeof(buf), tp, sizeof(tp));
    usz r = quic_tpext_decode(buf, w, &out, &olen);
    CHECK(w == 4 + sizeof(tp) && r == w);
    CHECK(olen == sizeof(tp) && out == buf + 4);
    for (usz i = 0; i < sizeof(tp); i++) CHECK(out[i] == tp[i]);
    /* wire framing: type 0x0039, length */
    CHECK(buf[0] == 0x00 && buf[1] == 0x39);
    CHECK(buf[2] == 0x00 && buf[3] == (u8)sizeof(tp));
}

static void test_tpext_empty(void)
{
    u8 buf[8];
    const u8 *out;
    usz olen;
    usz w = quic_tpext_encode(buf, sizeof(buf), (const u8 *)0, 0);
    usz r = quic_tpext_decode(buf, w, &out, &olen);
    CHECK(w == 4 && r == 4 && olen == 0);
}

static void test_tpext_wrong_type(void)
{
    u8 buf[8] = {0x00, 0x38, 0x00, 0x00};
    const u8 *out;
    usz olen;
    CHECK(quic_tpext_decode(buf, 4, &out, &olen) == 0);
}

static void test_tpext_bad_len(void)
{
    u8 buf[16];
    const u8 *out;
    usz olen;
    usz w = quic_tpext_encode(buf, sizeof(buf), (const u8 *)"abc", 3);
    /* length field claims 3 but only 2 data bytes are readable */
    CHECK(quic_tpext_decode(buf, w - 1, &out, &olen) == 0);
    /* no room to encode */
    CHECK(quic_tpext_encode(buf, 4, (const u8 *)"abc", 3) == 0);
}

void test_tpext(void)
{
    test_tpext_roundtrip();
    test_tpext_empty();
    test_tpext_wrong_type();
    test_tpext_bad_len();
}

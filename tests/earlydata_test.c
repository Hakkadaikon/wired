#include "test.h"

static void test_earlydata_ch_golden(void)
{
    u8 buf[8];
    usz w = 0;
    /* wire: type 0x002a, ext_data len 0x0000 */
    CHECK(quic_tlsext_early_data_ch(buf, sizeof(buf), &w) == 1);
    CHECK(w == 4);
    CHECK(buf[0] == 0x00 && buf[1] == 0x2a);
    CHECK(buf[2] == 0x00 && buf[3] == 0x00);
}

static void test_earlydata_nst_golden(void)
{
    u8 buf[16];
    usz w = 0;
    /* wire: type 0x002a, ext_data len 0x0004, max_early_data_size */
    CHECK(quic_tlsext_early_data_nst(0x01020304, buf, sizeof(buf), &w) == 1);
    CHECK(w == 8);
    CHECK(buf[0] == 0x00 && buf[1] == 0x2a);
    CHECK(buf[2] == 0x00 && buf[3] == 0x04);
    CHECK(buf[4] == 0x01 && buf[5] == 0x02 && buf[6] == 0x03 && buf[7] == 0x04);
}

static void test_earlydata_nst_roundtrip(void)
{
    u8 buf[16];
    usz w = 0;
    u32 got = 0;
    quic_tlsext_early_data_nst(0xdeadbeef, buf, sizeof(buf), &w);
    CHECK(quic_tlsext_early_data_nst_parse(buf, w, &got) == 1);
    CHECK(got == 0xdeadbeef);
}

static void test_earlydata_nst_guards(void)
{
    u8 buf[16];
    usz w = 0;
    u32 got = 0;
    quic_tlsext_early_data_nst(7, buf, sizeof(buf), &w);
    /* truncated */
    CHECK(quic_tlsext_early_data_nst_parse(buf, w - 1, &got) == 0);
    /* wrong type */
    buf[1] = 0x29;
    CHECK(quic_tlsext_early_data_nst_parse(buf, w, &got) == 0);
    /* ClientHello (empty) form is not a valid NST body */
    u8 ch[4] = {0x00, 0x2a, 0x00, 0x00};
    CHECK(quic_tlsext_early_data_nst_parse(ch, sizeof(ch), &got) == 0);
}

static void test_earlydata_encode_guards(void)
{
    u8 buf[8];
    usz w = 0;
    CHECK(quic_tlsext_early_data_ch(buf, 3, &w) == 0);
    CHECK(quic_tlsext_early_data_nst(1, buf, 7, &w) == 0);
}

void test_earlydata(void)
{
    test_earlydata_ch_golden();
    test_earlydata_nst_golden();
    test_earlydata_nst_roundtrip();
    test_earlydata_nst_guards();
    test_earlydata_encode_guards();
}

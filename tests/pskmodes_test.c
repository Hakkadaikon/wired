#include "test.h"

static void test_pskmodes_golden(void)
{
    u8 buf[16];
    usz w = 0;
    /* wire: type 0x002d, ext_data len 0x0002, list len 0x01, mode 0x01 */
    CHECK(quic_tlsext_psk_modes(buf, sizeof(buf), &w) == 1);
    CHECK(w == 6);
    CHECK(buf[0] == 0x00 && buf[1] == 0x2d);
    CHECK(buf[2] == 0x00 && buf[3] == 0x02);
    CHECK(buf[4] == 0x01);
    CHECK(buf[5] == 0x01);
}

static void test_pskmodes_roundtrip(void)
{
    u8 buf[16];
    usz w = 0;
    quic_tlsext_psk_modes(buf, sizeof(buf), &w);
    CHECK(quic_tlsext_psk_modes_parse(buf, w) == 1);
}

static void test_pskmodes_absent(void)
{
    /* type ok, single mode 0x00 (psk_ke) -> psk_dhe_ke not present */
    u8 buf[6] = {0x00, 0x2d, 0x00, 0x02, 0x01, 0x00};
    CHECK(quic_tlsext_psk_modes_parse(buf, sizeof(buf)) == 0);
}

static void test_pskmodes_guards(void)
{
    u8 buf[16];
    usz w = 0;
    quic_tlsext_psk_modes(buf, sizeof(buf), &w);
    /* truncated body */
    CHECK(quic_tlsext_psk_modes_parse(buf, w - 1) == 0);
    /* wrong extension_type */
    buf[1] = 0x2e;
    CHECK(quic_tlsext_psk_modes_parse(buf, w) == 0);
    /* list length disagrees with ext_data length */
    u8 bad[6] = {0x00, 0x2d, 0x00, 0x02, 0x02, 0x01};
    CHECK(quic_tlsext_psk_modes_parse(bad, sizeof(bad)) == 0);
}

static void test_pskmodes_encode_guard(void)
{
    u8 buf[5];
    usz w = 0;
    CHECK(quic_tlsext_psk_modes(buf, sizeof(buf), &w) == 0);
}

void test_pskmodes(void)
{
    test_pskmodes_golden();
    test_pskmodes_roundtrip();
    test_pskmodes_absent();
    test_pskmodes_guards();
    test_pskmodes_encode_guard();
}

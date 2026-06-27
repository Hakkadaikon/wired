#include "test.h"

/* RFC 9000 17.2: long header byte0 has high bit + fixed bit set (0xC0),
 * type in bits 5-4, then 4-byte version and two length-prefixed CIDs. */
static void test_header_parse_long(void)
{
    /* Initial: byte0=0xC0, version=1, DCID len 4, SCID len 0. */
    const u8 pkt[] = {0xC0, 0, 0, 0, 1, 4, 0xDE, 0xAD, 0xBE, 0xEF, 0};
    quic_header h;
    usz used = quic_header_parse(pkt, sizeof(pkt), &h);
    CHECK(used == sizeof(pkt));
    CHECK(h.form == QUIC_FORM_LONG && h.long_type == QUIC_LP_INITIAL);
    CHECK(h.version == 1 && h.dcid_len == 4 && h.scid_len == 0);
    CHECK(h.dcid[0] == 0xDE && h.dcid[3] == 0xEF);
}

static void test_header_parse_short(void)
{
    const u8 pkt[] = {0x40, 0x11, 0x22, 0x33, 0x44}; /* short form, DCID len 4 */
    quic_header h;
    h.dcid_len = 4; /* caller's known local CID length */
    usz used = quic_header_parse(pkt, sizeof(pkt), &h);
    CHECK(used == 5 && h.form == QUIC_FORM_SHORT && h.dcid[0] == 0x11);
}

static void test_header_build_roundtrip(void)
{
    quic_header in = {0};
    in.long_type = QUIC_LP_HANDSHAKE;
    in.version = 1;
    in.dcid_len = 4;
    in.dcid[0] = 0xDE; in.dcid[1] = 0xAD; in.dcid[2] = 0xBE; in.dcid[3] = 0xEF;
    in.scid_len = 2;
    in.scid[0] = 0xAB; in.scid[1] = 0xCD;

    u8 buf[64];
    usz w = quic_header_build_long(buf, sizeof(buf), &in);
    CHECK(w == 5 + 1 + 4 + 1 + 2);

    quic_header out;
    usz r = quic_header_parse(buf, w, &out);
    CHECK(r == w && out.long_type == QUIC_LP_HANDSHAKE && out.version == 1);
    CHECK(out.dcid_len == 4 && out.dcid[3] == 0xEF);
    CHECK(out.scid_len == 2 && out.scid[1] == 0xCD);
}

static void test_header_truncated(void)
{
    quic_header h;
    CHECK(quic_header_parse((const u8 *)"", 0, &h) == 0);
    /* claims DCID len 4 but only 2 bytes follow */
    const u8 bad[] = {0xC0, 0, 0, 0, 1, 4, 0xDE, 0xAD};
    CHECK(quic_header_parse(bad, sizeof(bad), &h) == 0);
    /* build into too-small buffer */
    u8 small[4];
    CHECK(quic_header_build_long(small, sizeof(small), &h) == 0);
}

void test_header(void)
{
    test_header_parse_long();
    test_header_parse_short();
    test_header_build_roundtrip();
    test_header_truncated();
}

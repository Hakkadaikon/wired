#include "test.h"

/* RFC 9000 17.2 complete long header assembly (Initial 17.2.2 / Handshake
 * 17.2.4): byte0, version, DCID, SCID, optional Token, Length, packet num. */

static void test_lhdr_byte0_pnlen(void)
{
    /* low two bits = pn_len-1; high six bits preserved (RFC 9000 17.2). */
    CHECK(quic_lhdr_byte0_pnlen(0xC0, 1) == 0xC0);
    CHECK(quic_lhdr_byte0_pnlen(0xC0, 2) == 0xC1);
    CHECK(quic_lhdr_byte0_pnlen(0xC0, 4) == 0xC3);
    CHECK(quic_lhdr_byte0_pnlen(0xC3, 1) == 0xC0); /* overwrites prior bits */
}

static void test_lhdr_initial_layout(void)
{
    const u8 dcid[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    const u8 scid[2] = {0xAB, 0xCD};
    u8 out[64];
    usz hdr_len = 0, len_off = 0;
    /* token absent, payload_len 100, pn=5, pn_len=2. */
    usz w = quic_lhdr_build(0xC0, 1, dcid, 4, scid, 2, 1, (const u8 *)0, 0,
                            100, 5, 2, out, sizeof(out), &hdr_len, &len_off);
    CHECK(w == hdr_len && w != 0);
    /* byte0 with pn_len-1=1, then 4-byte version. */
    CHECK(out[0] == 0xC1);
    CHECK(out[1] == 0 && out[2] == 0 && out[3] == 0 && out[4] == 1);
    /* DCID len + DCID. */
    CHECK(out[5] == 4 && out[6] == 0xDE && out[9] == 0xEF);
    /* SCID len + SCID. */
    CHECK(out[10] == 2 && out[11] == 0xAB && out[12] == 0xCD);
    /* Token Length = 0 (one varint byte). */
    CHECK(out[13] == 0);
    /* Length varint at len_off encodes pn_len+payload+16 = 2+100+16 = 118.
     * 118 > 63 so it needs the two-byte varint form: 0x4076. */
    CHECK(len_off == 14);
    CHECK(out[14] == 0x40 && out[15] == 0x76);
    /* packet number, 2 bytes big-endian = 0x0005. */
    CHECK(out[16] == 0x00 && out[17] == 0x05);
    CHECK(hdr_len == 18);
}

static void test_lhdr_initial_with_token(void)
{
    const u8 dcid[1] = {0x11};
    const u8 token[3] = {0xAA, 0xBB, 0xCC};
    u8 out[64];
    usz hdr_len = 0, len_off = 0;
    /* payload_len 10, pn=1, pn_len=1. */
    usz w = quic_lhdr_build(0xC0, 1, dcid, 1, (const u8 *)0, 0, 1, token, 3,
                            10, 1, 1, out, sizeof(out), &hdr_len, &len_off);
    CHECK(w != 0);
    /* byte0..version(5) + dcid(1+1) + scid(1) = offset 8 for token len. */
    CHECK(out[8] == 3); /* Token Length = 3 */
    CHECK(out[9] == 0xAA && out[10] == 0xBB && out[11] == 0xCC);
    /* Length = 1+10+16 = 27 (one varint byte) at offset 12. */
    CHECK(len_off == 12 && out[12] == 27);
    /* pn_len=1, pn=1 at offset 13. */
    CHECK(out[13] == 1 && hdr_len == 14);
    CHECK(out[0] == 0xC0); /* pn_len-1 = 0 */
}

static void test_lhdr_handshake_no_token(void)
{
    const u8 dcid[2] = {0x01, 0x02};
    const u8 scid[2] = {0x03, 0x04};
    u8 out[64];
    usz hdr_len = 0, len_off = 0;
    /* byte0 0xE0 = Handshake type (bits 5-4 = 0x2). pn_len=4, pn=0x01020304. */
    usz w = quic_lhdr_build(0xE0, 1, dcid, 2, scid, 2, 0, (const u8 *)0, 0,
                            50, 0x01020304, 4, out, sizeof(out), &hdr_len,
                            &len_off);
    CHECK(w != 0);
    CHECK(out[0] == 0xE3); /* Handshake + pn_len-1 = 3 */
    /* prefix: byte0..version(5) + dcid(1+2) + scid(1+2) = offset 11. No token:
     * Length varint starts immediately. */
    CHECK(len_off == 11);
    /* Length = 4+50+16 = 70 > 63, two-byte varint 0x4046 at offset 11. */
    CHECK(out[11] == 0x40 && out[12] == 0x46);
    /* 4-byte pn big-endian at offset 13. */
    CHECK(out[13] == 0x01 && out[14] == 0x02 && out[15] == 0x03 &&
          out[16] == 0x04);
    CHECK(hdr_len == 17);
}

static void test_lhdr_cap_overflow(void)
{
    const u8 dcid[4] = {0, 0, 0, 0};
    u8 out[8];
    usz hdr_len = 0, len_off = 0;
    /* 8 bytes cannot hold byte0+version+DCID(1+4)+... */
    usz w = quic_lhdr_build(0xC0, 1, dcid, 4, (const u8 *)0, 0, 1,
                            (const u8 *)0, 0, 0, 0, 1, out, sizeof(out),
                            &hdr_len, &len_off);
    CHECK(w == 0);
}

/* RFC 9001 A.2: the worked Initial example. DCID = 8394c8f03e515708,
 * empty token, Length = 0x449e (1182), pn = 2 with pn_len 4. The plaintext
 * header is c300000001088394c8f03e51570800 00449e00000002. */
static void test_lhdr_rfc9001_a2(void)
{
    const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0,
                        0x3e, 0x51, 0x57, 0x08};
    const u8 expect[] = {0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94,
                         0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00, 0x00,
                         0x44, 0x9e, 0x00, 0x00, 0x00, 0x02};
    u8 out[64];
    usz hdr_len = 0, len_off = 0;
    /* Length 0x449e = pn_len(4) + payload_len + 16 -> payload_len = 1162. */
    usz w = quic_lhdr_build(0xc0, 1, dcid, 8, (const u8 *)0, 0, 1,
                            (const u8 *)0, 0, 1162, 2, 4, out, sizeof(out),
                            &hdr_len, &len_off);
    CHECK(w == sizeof(expect));
    int match = 1;
    for (usz i = 0; i < sizeof(expect); i++)
        if (out[i] != expect[i]) match = 0;
    CHECK(match);
    /* Length field is the two-byte varint 0x449e at its recorded offset. */
    CHECK(out[len_off] == 0x44 && out[len_off + 1] == 0x9e);
}

void test_lhdr_build(void)
{
    test_lhdr_byte0_pnlen();
    test_lhdr_initial_layout();
    test_lhdr_initial_with_token();
    test_lhdr_handshake_no_token();
    test_lhdr_cap_overflow();
    test_lhdr_rfc9001_a2();
}

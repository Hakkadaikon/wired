#include "test.h"

/* RFC 9000 17.2.2 Initial: byte0 | version | DCID | SCID | Token | Length.
 * DCID=AA BB (len 2), SCID=CC (len 1), Token=DE AD (len 2), Length=0x40 0x09
 * (2-byte varint, value 9). pn_off lands just past the Length field. */
static void test_lhdr_initial(void)
{
    u8 p[32];
    usz n = 0;
    p[n++] = 0xC0;                                  /* long, Initial */
    p[n++] = 0; p[n++] = 0; p[n++] = 0; p[n++] = 1; /* version 1 */
    p[n++] = 2; p[n++] = 0xAA; p[n++] = 0xBB;       /* DCID */
    p[n++] = 1; p[n++] = 0xCC;                      /* SCID */
    p[n++] = 2; p[n++] = 0xDE; p[n++] = 0xAD;       /* Token len 2 + token */
    usz len_off = n;
    p[n++] = 0x40; p[n++] = 0x09;                   /* Length varint = 9 */
    usz want_pn_off = n;

    const u8 *dcid, *scid, *token;
    u8 dcl, scl;
    usz tkl, pn_off;
    u64 length;
    int ok = quic_lhdr_parse(p, n, 1, &dcid, &dcl, &scid, &scl, &token, &tkl,
                             &length, &pn_off);
    CHECK(ok == 1);
    CHECK(dcl == 2 && dcid[0] == 0xAA && dcid[1] == 0xBB);
    CHECK(scl == 1 && scid[0] == 0xCC);
    CHECK(tkl == 2 && token[0] == 0xDE && token[1] == 0xAD);
    CHECK(length == 9);
    CHECK(pn_off == want_pn_off);
    CHECK(len_off == 13); /* DCID/SCID/token consumed before Length */
}

/* RFC 9000 17.2.4 Handshake: no Token field. is_initial = 0. */
static void test_lhdr_handshake(void)
{
    u8 p[32];
    usz n = 0;
    p[n++] = 0xE0;                                  /* long, Handshake type */
    p[n++] = 0; p[n++] = 0; p[n++] = 0; p[n++] = 1; /* version 1 */
    p[n++] = 1; p[n++] = 0x11;                      /* DCID */
    p[n++] = 0;                                     /* SCID len 0 */
    p[n++] = 5;                                     /* Length varint = 5 */
    usz want_pn_off = n;

    const u8 *dcid, *scid, *token;
    u8 dcl, scl;
    usz tkl, pn_off;
    u64 length;
    int ok = quic_lhdr_parse(p, n, 0, &dcid, &dcl, &scid, &scl, &token, &tkl,
                             &length, &pn_off);
    CHECK(ok == 1);
    CHECK(dcl == 1 && dcid[0] == 0x11);
    CHECK(scl == 0);
    CHECK(token == (const u8 *)0 && tkl == 0);
    CHECK(length == 5);
    CHECK(pn_off == want_pn_off);
}

/* A short-header byte0 (high bit clear) is not a long header. */
static void test_lhdr_not_long(void)
{
    u8 p[8] = {0x40, 0, 0, 0, 1, 0, 0, 0};
    const u8 *dcid, *scid, *token;
    u8 dcl, scl;
    usz tkl, pn_off;
    u64 length;
    CHECK(quic_lhdr_parse(p, 8, 1, &dcid, &dcl, &scid, &scl, &token, &tkl,
                          &length, &pn_off) == 0);
}

/* Truncation: a DCID length that overruns the buffer parses to 0. */
static void test_lhdr_truncated(void)
{
    u8 p[8];
    usz n = 0;
    p[n++] = 0xC0;
    p[n++] = 0; p[n++] = 0; p[n++] = 0; p[n++] = 1;
    p[n++] = 20;            /* DCID len 20 but only 2 bytes remain */
    p[n++] = 0xAA; p[n++] = 0xBB;
    const u8 *dcid, *scid, *token;
    u8 dcl, scl;
    usz tkl, pn_off;
    u64 length;
    CHECK(quic_lhdr_parse(p, n, 1, &dcid, &dcl, &scid, &scl, &token, &tkl,
                          &length, &pn_off) == 0);
}

/* Missing Length field after a valid prefix parses to 0. */
static void test_lhdr_no_length(void)
{
    u8 p[8];
    usz n = 0;
    p[n++] = 0xE0;
    p[n++] = 0; p[n++] = 0; p[n++] = 0; p[n++] = 1;
    p[n++] = 0;             /* DCID len 0 */
    p[n++] = 0;             /* SCID len 0 */
    /* Handshake: next would be Length, but buffer ends here. */
    const u8 *dcid, *scid, *token;
    u8 dcl, scl;
    usz tkl, pn_off;
    u64 length;
    CHECK(quic_lhdr_parse(p, n, 0, &dcid, &dcl, &scid, &scl, &token, &tkl,
                          &length, &pn_off) == 0);
}

/* RFC 9000 17.2: pn_len is (byte0 & 0x03) + 1 after HP removal. */
static void test_lhdr_pn_len(void)
{
    CHECK(quic_lhdr_pn_len(0xC0) == 1);
    CHECK(quic_lhdr_pn_len(0xC1) == 2);
    CHECK(quic_lhdr_pn_len(0xC2) == 3);
    CHECK(quic_lhdr_pn_len(0xC3) == 4);
}

void test_lhdr_parse(void)
{
    test_lhdr_initial();
    test_lhdr_handshake();
    test_lhdr_not_long();
    test_lhdr_truncated();
    test_lhdr_no_length();
    test_lhdr_pn_len();
}

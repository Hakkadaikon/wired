#include "test.h"
#include "qpack/literal.h"

/* RFC 9204 4.5.4: N=0,T=1,index=1 (01010001=0x51), value "/" (0x01 0x2f). */
static void test_literal_namref_golden(void)
{
    const u8 v[] = {'/'};
    u8 buf[8];
    usz w = quic_qpack_literal_namref_encode(buf, sizeof(buf), 1, 1, 0, v, 1);
    CHECK(w == 3 && buf[0] == 0x51 && buf[1] == 0x01 && buf[2] == 0x2f);

    u64 idx;
    int st, nv;
    u8 out[8];
    usz olen;
    usz r = quic_qpack_literal_namref_decode(buf, w, &idx, &st, &nv, out,
                                             sizeof(out), &olen);
    CHECK(r == w && idx == 1 && st == 1 && nv == 0);
    CHECK(olen == 1 && out[0] == '/');
}

/* Never-indexed and dynamic-table flags round-trip in the name-reference form. */
static void test_literal_namref_flags(void)
{
    const u8 v[] = {'a', 'b'};
    u8 buf[8];
    usz w = quic_qpack_literal_namref_encode(buf, sizeof(buf), 3, 0, 1, v, 2);
    /* 01NTiiii: N=1,T=0,index=3 -> 0110 0011 = 0x63. */
    CHECK(w != 0 && buf[0] == 0x63);

    u64 idx;
    int st, nv;
    u8 out[8];
    usz olen;
    usz r = quic_qpack_literal_namref_decode(buf, w, &idx, &st, &nv, out,
                                             sizeof(out), &olen);
    CHECK(r == w && idx == 3 && st == 0 && nv == 1 && olen == 2);
    CHECK(out[0] == 'a' && out[1] == 'b');
}

/* A first byte not matching 01xxxxxx is not a name-reference field line. */
static void test_literal_namref_reject(void)
{
    u8 bad = 0x80;
    u64 idx;
    int st, nv;
    u8 out[8];
    usz olen;
    CHECK(quic_qpack_literal_namref_decode(&bad, 1, &idx, &st, &nv, out,
                                           sizeof(out), &olen) == 0);
}

/* RFC 9204 4.5.6: N=0,H=0,name "x" (00100001=0x21, 0x78), value "y". */
static void test_literal_name_golden(void)
{
    const u8 nm[] = {'x'};
    const u8 v[] = {'y'};
    u8 buf[8];
    usz w = quic_qpack_literal_name_encode(buf, sizeof(buf), 0, nm, 1, v, 1);
    CHECK(w == 4 && buf[0] == 0x21 && buf[1] == 0x78);
    CHECK(buf[2] == 0x01 && buf[3] == 0x79);

    int nv;
    u8 outn[8], outv[8];
    usz nlen, vlen;
    usz r = quic_qpack_literal_name_decode(buf, w, &nv, outn, sizeof(outn),
                                           &nlen, outv, sizeof(outv), &vlen);
    CHECK(r == w && nv == 0 && nlen == 1 && outn[0] == 'x');
    CHECK(vlen == 1 && outv[0] == 'y');
}

/* A name length of 7 fills the 3-bit prefix, spilling the length integer. */
static void test_literal_name_prefix_boundary(void)
{
    const u8 nm[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g'};
    const u8 v[] = {'z'};
    u8 buf[16];
    usz w = quic_qpack_literal_name_encode(buf, sizeof(buf), 0, nm, 7, v, 1);
    /* 001NHiii with iii=111 then a 0x00 continuation byte for 7-7=0. */
    CHECK(w != 0 && buf[0] == 0x27 && buf[1] == 0x00);

    int nv;
    u8 outn[8], outv[8];
    usz nlen, vlen;
    usz r = quic_qpack_literal_name_decode(buf, w, &nv, outn, sizeof(outn),
                                           &nlen, outv, sizeof(outv), &vlen);
    CHECK(r == w && nlen == 7 && outn[6] == 'g' && vlen == 1 && outv[0] == 'z');
}

/* H=1 (Huffman name) is rejected; so is a non-001 pattern. */
static void test_literal_name_reject(void)
{
    u8 huff = 0x28; /* 001 0 1 000: H set */
    u8 wrong = 0x40;
    int nv;
    u8 outn[8], outv[8];
    usz nlen, vlen;
    CHECK(quic_qpack_literal_name_decode(&huff, 1, &nv, outn, sizeof(outn),
                                         &nlen, outv, sizeof(outv), &vlen) == 0);
    CHECK(quic_qpack_literal_name_decode(&wrong, 1, &nv, outn, sizeof(outn),
                                         &nlen, outv, sizeof(outv), &vlen) == 0);
}

void test_literal(void)
{
    test_literal_namref_golden();
    test_literal_namref_flags();
    test_literal_namref_reject();
    test_literal_name_golden();
    test_literal_name_prefix_boundary();
    test_literal_name_reject();
}

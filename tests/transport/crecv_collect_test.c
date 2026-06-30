#include "test.h"

/* Build a CRYPTO frame (RFC 9000 19.6): type 0x06, varint offset, varint
 * length, data. Offsets/lengths here stay < 64 so each varint is one byte. */
static usz mk_crypto(u8 *out, u8 offset, const u8 *data, u8 len)
{
    usz i = 0;
    out[i++] = 0x06;
    out[i++] = offset;
    out[i++] = len;
    for (u8 j = 0; j < len; j++) out[i++] = data[j];
    return i;
}

static void test_crecv_single_offset0(void)
{
    quic_crecv s;
    const u8 vd[] = {0x14, 0, 0, 32, 1, 2, 3, 4}; /* Finished hdr + body start */
    u8 frame[64];
    usz n = mk_crypto(frame, 0, vd, sizeof vd);

    quic_crecv_init(&s);
    CHECK(quic_crecv_collect(&s, frame, n) == 1);
    CHECK(s.received_to == sizeof vd);
    for (usz i = 0; i < sizeof vd; i++) CHECK(s.buf[i] == vd[i]);
}

static void test_crecv_out_of_order(void)
{
    quic_crecv s;
    const u8 a[] = {0xaa, 0xbb};
    const u8 b[] = {0xcc, 0xdd};
    u8 f[64];
    usz n;

    quic_crecv_init(&s);
    n = mk_crypto(f, 2, b, sizeof b);          /* later chunk first */
    CHECK(quic_crecv_collect(&s, f, n) == 1);
    CHECK(s.received_to == 0);                 /* gap at start */
    n = mk_crypto(f, 0, a, sizeof a);          /* now the head */
    CHECK(quic_crecv_collect(&s, f, n) == 1);
    CHECK(s.received_to == 4);
    CHECK(s.buf[0] == 0xaa);
    CHECK(s.buf[3] == 0xdd);
}

static void test_crecv_two_frames_one_payload(void)
{
    quic_crecv s;
    const u8 a[] = {1, 2};
    const u8 b[] = {3, 4};
    u8 f[64];
    usz n = mk_crypto(f, 0, a, sizeof a);
    n += mk_crypto(f + n, 2, b, sizeof b);

    quic_crecv_init(&s);
    CHECK(quic_crecv_collect(&s, f, n) == 1);
    CHECK(s.received_to == 4);
}

static void test_crecv_gap_stays_incomplete(void)
{
    quic_crecv s;
    const u8 b[] = {9, 9};
    u8 f[64];
    usz n = mk_crypto(f, 5, b, sizeof b); /* offset 5, nothing at 0..4 */

    quic_crecv_init(&s);
    CHECK(quic_crecv_collect(&s, f, n) == 1);
    CHECK(s.received_to == 0);
}

static void test_crecv_ignores_non_crypto(void)
{
    quic_crecv s;
    const u8 cd[] = {7, 7, 7};
    u8 f[64];
    usz n = 0;
    f[n++] = 0x00;                        /* PADDING */
    f[n++] = 0x01;                        /* PING */
    n += mk_crypto(f + n, 0, cd, sizeof cd);

    quic_crecv_init(&s);
    CHECK(quic_crecv_collect(&s, f, n) == 1);
    CHECK(s.received_to == sizeof cd);
}

static void test_crecv_overflow_rejected(void)
{
    quic_crecv s;
    u8 f[8];
    usz n = 0;
    /* offset 2047 as a 2-byte varint (0x4000 | value), length 2 ends at 2049,
     * one past QUIC_CRECV_BUF=2048 -> rejected (RFC 9000 19.6). */
    f[n++] = 0x06;
    f[n++] = 0x47; f[n++] = 0xff;         /* offset 0x07ff = 2047 */
    f[n++] = 0x02;                        /* length 2 */
    f[n++] = 1; f[n++] = 2;

    quic_crecv_init(&s);
    CHECK(quic_crecv_collect(&s, f, n) == 0);
}

void test_crecv_collect(void)
{
    test_crecv_single_offset0();
    test_crecv_out_of_order();
    test_crecv_two_frames_one_payload();
    test_crecv_gap_stays_incomplete();
    test_crecv_ignores_non_crypto();
    test_crecv_overflow_rejected();
}

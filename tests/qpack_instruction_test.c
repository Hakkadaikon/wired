#include "test.h"

/* Every encoder-stream instruction round-trips its integer field and its kind
 * is recovered from the leading bit pattern (RFC 9204 4.3). */
static void test_qpack_enc_instr_roundtrip(void)
{
    quic_qpack_enc_kind kinds[] = {
        QUIC_QPACK_ENC_SET_CAPACITY, QUIC_QPACK_ENC_INSERT_NAME_REF,
        QUIC_QPACK_ENC_INSERT_LITERAL, QUIC_QPACK_ENC_DUPLICATE,
    };
    for (usz i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
        u8 buf[8];
        usz w = quic_qpack_enc_instr_encode(buf, sizeof(buf), kinds[i], 1337);
        CHECK(w != 0);
        quic_qpack_enc_kind k;
        u64 v;
        usz r = quic_qpack_enc_instr_decode(buf, w, &k, &v);
        CHECK(r == w && k == kinds[i] && v == 1337);
    }
}

/* Every decoder-stream instruction round-trips (RFC 9204 4.4). */
static void test_qpack_dec_instr_roundtrip(void)
{
    quic_qpack_dec_kind kinds[] = {
        QUIC_QPACK_DEC_SECTION_ACK, QUIC_QPACK_DEC_STREAM_CANCEL,
        QUIC_QPACK_DEC_INSERT_COUNT,
    };
    for (usz i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
        u8 buf[8];
        usz w = quic_qpack_dec_instr_encode(buf, sizeof(buf), kinds[i], 42);
        CHECK(w != 0);
        quic_qpack_dec_kind k;
        u64 v;
        usz r = quic_qpack_dec_instr_decode(buf, w, &k, &v);
        CHECK(r == w && k == kinds[i] && v == 42);
    }
}

/* The leading byte's pattern bits select the kind: Section Acknowledgment
 * (1xxxxxxx) versus Insert Count Increment (00xxxxxx) at value 0. */
static void test_qpack_instr_pattern(void)
{
    u8 buf[2];
    quic_qpack_dec_instr_encode(buf, sizeof(buf), QUIC_QPACK_DEC_SECTION_ACK, 0);
    CHECK((buf[0] & 0x80) == 0x80);
    quic_qpack_dec_instr_encode(buf, sizeof(buf), QUIC_QPACK_DEC_INSERT_COUNT, 0);
    CHECK((buf[0] & 0xc0) == 0x00);
    quic_qpack_dec_instr_encode(buf, sizeof(buf), QUIC_QPACK_DEC_STREAM_CANCEL, 0);
    CHECK((buf[0] & 0xc0) == 0x40);
}

/* Truncation and zero-length input are rejected. */
static void test_qpack_instr_truncated(void)
{
    u8 buf[8];
    /* A value needing a continuation byte, then cut to just the prefix byte. */
    usz w = quic_qpack_enc_instr_encode(buf, sizeof(buf), QUIC_QPACK_ENC_DUPLICATE, 1000);
    CHECK(w > 1);
    quic_qpack_enc_kind k;
    u64 v;
    CHECK(quic_qpack_enc_instr_decode(buf, w - 1, &k, &v) == 0);
    CHECK(quic_qpack_enc_instr_decode(buf, 0, &k, &v) == 0);
}

void test_qpack_instruction(void)
{
    test_qpack_enc_instr_roundtrip();
    test_qpack_dec_instr_roundtrip();
    test_qpack_instr_pattern();
    test_qpack_instr_truncated();
}

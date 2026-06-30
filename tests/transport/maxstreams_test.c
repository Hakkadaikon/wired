#include "test.h"

/* RFC 9000 19.11: MAX_STREAMS bidi=0x12, uni=0x13, then a varint count. */
static void test_maxstreams_frame_bidi_wire(void)
{
    u8 out[8];
    usz len = 0;
    CHECK(quic_maxstreams_frame(0, 3, out, sizeof out, &len) == 1);
    CHECK(len == 2);
    CHECK(out[0] == 0x12);
    CHECK(out[1] == 0x03); /* single-byte varint */
}

static void test_maxstreams_frame_uni_wire(void)
{
    u8 out[8];
    usz len = 0;
    CHECK(quic_maxstreams_frame(1, 5, out, sizeof out, &len) == 1);
    CHECK(out[0] == 0x13);
    CHECK(out[1] == 0x05);
}

static void test_maxstreams_frame_overflow(void)
{
    u8 out[1];
    usz len = 99;
    CHECK(quic_maxstreams_frame(0, 3, out, sizeof out, &len) == 0);
    CHECK(len == 99); /* untouched on failure */
}

static void test_maxstreams_roundtrip(void)
{
    u8 out[8];
    usz len = 0;
    int uni = -1;
    u64 max = 0;
    quic_maxstreams_frame(1, 100, out, sizeof out, &len);
    CHECK(quic_maxstreams_parse(out, len, &uni, &max) == 1);
    CHECK(uni == 1);
    CHECK(max == 100);
}

static void test_maxstreams_parse_truncated(void)
{
    u8 buf[1] = {0x12}; /* type only, varint missing */
    int uni = 0;
    u64 max = 0;
    CHECK(quic_maxstreams_parse(buf, sizeof buf, &uni, &max) == 0);
}

/* RFC 9000 4.6: admission boundary at the limit. */
static void test_maxstreams_can_open_boundary(void)
{
    CHECK(quic_maxstreams_can_open(2, 3) == 1); /* below limit */
    CHECK(quic_maxstreams_can_open(3, 3) == 0); /* at limit: STREAM_LIMIT */
    CHECK(quic_maxstreams_can_open(4, 3) == 0); /* over limit */
    CHECK(quic_maxstreams_can_open(0, 0) == 0); /* zero grant blocks all */
}

void test_maxstreams(void)
{
    test_maxstreams_frame_bidi_wire();
    test_maxstreams_frame_uni_wire();
    test_maxstreams_frame_overflow();
    test_maxstreams_roundtrip();
    test_maxstreams_parse_truncated();
    test_maxstreams_can_open_boundary();
}

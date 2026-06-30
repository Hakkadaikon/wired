#include "test.h"

static void test_max_data(void)
{
    quic_data_frame in = {.value = 1048576};
    u8 buf[16];
    usz w = quic_max_data_encode(buf, sizeof(buf), &in);
    CHECK(w != 0 && buf[0] == QUIC_FRAME_MAX_DATA);

    quic_data_frame out;
    usz r = quic_max_data_decode(buf, w, &out);
    CHECK(r == w && out.value == 1048576);
    CHECK(quic_max_data_decode(buf, w - 1, &out) == 0);
}

static void test_data_blocked(void)
{
    quic_data_frame in = {.value = 65536};
    u8 buf[16];
    usz w = quic_data_blocked_encode(buf, sizeof(buf), &in);
    CHECK(w != 0 && buf[0] == QUIC_FRAME_DATA_BLOCKED);

    quic_data_frame out;
    usz r = quic_data_blocked_decode(buf, w, &out);
    CHECK(r == w && out.value == 65536);
    CHECK(quic_data_blocked_decode(buf, w - 1, &out) == 0);
}

static void test_max_stream_data(void)
{
    quic_stream_data_frame in = {.stream_id = 4, .value = 16384};
    u8 buf[16];
    usz w = quic_max_stream_data_encode(buf, sizeof(buf), &in);
    CHECK(w != 0 && buf[0] == QUIC_FRAME_MAX_STREAM_DATA);

    quic_stream_data_frame out;
    usz r = quic_max_stream_data_decode(buf, w, &out);
    CHECK(r == w && out.stream_id == 4 && out.value == 16384);
    CHECK(quic_max_stream_data_decode(buf, w - 1, &out) == 0);
}

static void test_stream_data_blocked(void)
{
    quic_stream_data_frame in = {.stream_id = 8, .value = 100};
    u8 buf[16];
    usz w = quic_stream_data_blocked_encode(buf, sizeof(buf), &in);
    CHECK(w != 0 && buf[0] == QUIC_FRAME_STREAM_DATA_BLOCKED);

    quic_stream_data_frame out;
    usz r = quic_stream_data_blocked_decode(buf, w, &out);
    CHECK(r == w && out.stream_id == 8 && out.value == 100);
    CHECK(quic_stream_data_blocked_decode(buf, w - 1, &out) == 0);
}

static void test_max_streams_bidi(void)
{
    quic_streams_frame in = {.max_streams = 50, .uni = 0};
    u8 buf[16];
    usz w = quic_max_streams_encode(buf, sizeof(buf), &in);
    CHECK(w != 0 && buf[0] == QUIC_FRAME_MAX_STREAMS_BIDI);

    quic_streams_frame out;
    usz r = quic_max_streams_decode(buf, w, &out);
    CHECK(r == w && out.max_streams == 50 && out.uni == 0);
    CHECK(quic_max_streams_decode(buf, w - 1, &out) == 0);
}

static void test_max_streams_uni(void)
{
    quic_streams_frame in = {.max_streams = 7, .uni = 1};
    u8 buf[16];
    usz w = quic_max_streams_encode(buf, sizeof(buf), &in);
    CHECK(w != 0 && buf[0] == QUIC_FRAME_MAX_STREAMS_UNI);

    quic_streams_frame out;
    usz r = quic_max_streams_decode(buf, w, &out);
    CHECK(r == w && out.max_streams == 7 && out.uni == 1);
}

static void test_streams_blocked_bidi(void)
{
    quic_streams_frame in = {.max_streams = 12, .uni = 0};
    u8 buf[16];
    usz w = quic_streams_blocked_encode(buf, sizeof(buf), &in);
    CHECK(w != 0 && buf[0] == QUIC_FRAME_STREAMS_BLOCKED_BIDI);

    quic_streams_frame out;
    usz r = quic_streams_blocked_decode(buf, w, &out);
    CHECK(r == w && out.max_streams == 12 && out.uni == 0);
    CHECK(quic_streams_blocked_decode(buf, w - 1, &out) == 0);
}

static void test_streams_blocked_uni(void)
{
    quic_streams_frame in = {.max_streams = 3, .uni = 1};
    u8 buf[16];
    usz w = quic_streams_blocked_encode(buf, sizeof(buf), &in);
    CHECK(w != 0 && buf[0] == QUIC_FRAME_STREAMS_BLOCKED_UNI);

    quic_streams_frame out;
    usz r = quic_streams_blocked_decode(buf, w, &out);
    CHECK(r == w && out.max_streams == 3 && out.uni == 1);
}

void test_flowctl(void)
{
    test_max_data();
    test_data_blocked();
    test_max_stream_data();
    test_stream_data_blocked();
    test_max_streams_bidi();
    test_max_streams_uni();
    test_streams_blocked_bidi();
    test_streams_blocked_uni();
}

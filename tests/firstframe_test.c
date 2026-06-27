#include "test.h"

/* The control stream's first frame must be SETTINGS. */
static void test_firstframe_control(void)
{
    CHECK(quic_h3_first_frame_ok(QUIC_H3_STREAM_KIND_CONTROL,
                                 QUIC_H3_FRAME_SETTINGS) == 1);
    CHECK(quic_h3_first_frame_ok(QUIC_H3_STREAM_KIND_CONTROL,
                                 QUIC_H3_FRAME_HEADERS) == 0);
    CHECK(quic_h3_first_frame_ok(QUIC_H3_STREAM_KIND_CONTROL,
                                 QUIC_H3_FRAME_DATA) == 0);
}

/* A request stream's first frame must be HEADERS. */
static void test_firstframe_request(void)
{
    CHECK(quic_h3_first_frame_ok(QUIC_H3_STREAM_KIND_REQUEST,
                                 QUIC_H3_FRAME_HEADERS) == 1);
    CHECK(quic_h3_first_frame_ok(QUIC_H3_STREAM_KIND_REQUEST,
                                 QUIC_H3_FRAME_DATA) == 0);
    CHECK(quic_h3_first_frame_ok(QUIC_H3_STREAM_KIND_REQUEST,
                                 QUIC_H3_FRAME_SETTINGS) == 0);
}

void test_firstframe(void)
{
    test_firstframe_control();
    test_firstframe_request();
}

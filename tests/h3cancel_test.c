#include "test.h"

/* RFC 9114 4.1.1: cancelling a request emits RESET_STREAM then STOP_SENDING,
 * both with H3_REQUEST_CANCELLED (0x010c) on the request stream. */
static void test_h3cancel_request_builds_both_frames(void)
{
    u8 out[64];
    usz len = 0;
    quic_reset_stream_frame rs;
    quic_stop_sending_frame ss;
    usz rn;

    CHECK(quic_h3cancel_request(8, 100, out, sizeof out, &len) == 1);
    CHECK(len > 0);

    /* First frame: RESET_STREAM (type 0x04 at out[0]). */
    CHECK(out[0] == QUIC_FRAME_RESET_STREAM);
    rn = quic_reset_stream_decode(out, len, &rs);
    CHECK(rn > 0);
    CHECK(rs.stream_id == 8);
    CHECK(rs.error_code == QUIC_H3_REQUEST_CANCELLED);
    CHECK(rs.final_size == 100);

    /* Second frame: STOP_SENDING follows immediately (type 0x05). */
    CHECK(out[rn] == QUIC_FRAME_STOP_SENDING);
    CHECK(quic_stop_sending_decode(out + rn, len - rn, &ss) == len - rn);
    CHECK(ss.stream_id == 8);
    CHECK(ss.error_code == QUIC_H3_REQUEST_CANCELLED);
}

/* Boundary: a varint-max stream id still round-trips through the pair. */
static void test_h3cancel_request_large_ids(void)
{
    u8 out[64];
    usz len = 0;
    quic_reset_stream_frame rs;
    usz rn;

    CHECK(quic_h3cancel_request(0x3fffffffffffffffULL, 0,
                                out, sizeof out, &len) == 1);
    rn = quic_reset_stream_decode(out, len, &rs);
    CHECK(rn > 0);
    CHECK(rs.stream_id == 0x3fffffffffffffffULL);
    CHECK(rs.final_size == 0);
}

/* A buffer too small for both frames is rejected, not truncated. */
static void test_h3cancel_request_overflow(void)
{
    u8 out[3];
    usz len = 99;

    CHECK(quic_h3cancel_request(8, 100, out, sizeof out, &len) == 0);
}

/* CANCEL_PUSH codec (RFC 9114 7.2.3) is reused from h3/frame.c. */
static void test_h3cancel_push_roundtrip(void)
{
    u8 out[8];
    u64 id = 0;
    usz n = quic_h3_cancel_push_put(out, sizeof out, 0x4142);

    CHECK(n > 0);
    CHECK(out[0] == QUIC_H3_FRAME_CANCEL_PUSH);
    CHECK(quic_h3_cancel_push_get(out, n, &id) == n);
    CHECK(id == 0x4142);
}

static void test_h3cancel_push_truncated(void)
{
    u8 out[8];
    usz n = quic_h3_cancel_push_put(out, sizeof out, 0x4142);

    CHECK(quic_h3_cancel_push_get(out, n - 1, &(u64){0}) == 0);
}

static void test_h3cancel_error_code_value(void)
{
    CHECK(QUIC_H3_REQUEST_CANCELLED == 0x010c);
}

void test_h3cancel(void)
{
    test_h3cancel_request_builds_both_frames();
    test_h3cancel_request_large_ids();
    test_h3cancel_request_overflow();
    test_h3cancel_push_roundtrip();
    test_h3cancel_push_truncated();
    test_h3cancel_error_code_value();
}

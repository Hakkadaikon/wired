#include "test.h"

/* RFC 9114 4.1: a request stream begins with a HEADERS frame. */
static void test_req_frames_headers_first(void)
{
    u8 fs[] = {0xaa, 0xbb, 0xcc};
    u8 buf[16];
    usz n = quic_h3_frame_put(buf, sizeof(buf), QUIC_H3_FRAME_HEADERS, fs, sizeof(fs));
    const u8 *out;
    usz olen;
    CHECK(quic_h3req_recv_first_headers(buf, n, &out, &olen) == 1);
    CHECK(olen == sizeof(fs));
    CHECK(out[0] == 0xaa && out[2] == 0xcc);
}

static void test_req_frames_data_first(void)
{
    u8 body[] = {0x01};
    u8 buf[16];
    usz n = quic_h3_frame_put(buf, sizeof(buf), QUIC_H3_FRAME_DATA, body, sizeof(body));
    const u8 *out;
    usz olen;
    CHECK(quic_h3req_recv_first_headers(buf, n, &out, &olen) == 0);
}

static void test_req_frames_truncated(void)
{
    u8 buf[1] = {QUIC_H3_FRAME_HEADERS};
    const u8 *out;
    usz olen;
    /* length varint missing -> no complete frame. */
    CHECK(quic_h3req_recv_first_headers(buf, 1, &out, &olen) == 0);
}

void test_req_frames(void)
{
    test_req_frames_headers_first();
    test_req_frames_data_first();
    test_req_frames_truncated();
}

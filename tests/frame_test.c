#include "test.h"
#include "frame/frame.c"

static void test_frame_simple(void)
{
    u8 buf[4];
    CHECK(quic_frame_put_simple(buf, sizeof(buf), QUIC_FRAME_PING) == 1 &&
          buf[0] == 0x01);
    CHECK(quic_frame_put_simple(buf, sizeof(buf), QUIC_FRAME_PADDING) == 1 &&
          buf[0] == 0x00);
    CHECK(quic_frame_put_simple(buf, 0, QUIC_FRAME_PING) == 0);
}

static void test_frame_crypto_roundtrip(void)
{
    const u8 payload[] = {0x16, 0x03, 0x03, 0xAA, 0xBB};
    quic_crypto_frame in = {.offset = 1000, .length = sizeof(payload),
                            .data = payload};
    u8 buf[32];
    usz w = quic_frame_put_crypto(buf, sizeof(buf), &in);
    CHECK(w != 0 && buf[0] == QUIC_FRAME_CRYPTO);

    quic_crypto_frame out;
    usz r = quic_frame_get_crypto(buf, w, &out);
    CHECK(r == w && out.offset == 1000 && out.length == sizeof(payload));
    CHECK(out.data[0] == 0x16 && out.data[4] == 0xBB);
}

static void test_frame_crypto_truncated(void)
{
    const u8 payload[] = {1, 2, 3};
    quic_crypto_frame in = {.offset = 0, .length = 3, .data = payload};
    u8 buf[32];
    usz w = quic_frame_put_crypto(buf, sizeof(buf), &in);
    quic_crypto_frame out;
    CHECK(quic_frame_get_crypto(buf, w - 1, &out) == 0); /* data cut short */
    CHECK(quic_frame_put_crypto(buf, 2, &in) == 0);      /* header no room */
}

static void check_stream_roundtrip(u64 sid, u64 off, u8 fin)
{
    const u8 payload[] = {0xDE, 0xAD, 0xBE, 0xEF};
    quic_stream_frame in = {.stream_id = sid, .offset = off,
                            .length = sizeof(payload), .data = payload,
                            .fin = fin};
    u8 buf[32];
    usz w = quic_frame_put_stream(buf, sizeof(buf), &in);
    CHECK(w != 0 && (buf[0] & 0xF8) == QUIC_FRAME_STREAM_BASE);

    quic_stream_frame out;
    usz r = quic_frame_get_stream(buf, w, &out);
    CHECK(r == w && out.stream_id == sid && out.offset == off);
    CHECK(out.length == sizeof(payload) && out.fin == fin);
    CHECK(out.data[0] == 0xDE && out.data[3] == 0xEF);
}

static void test_frame_stream(void)
{
    check_stream_roundtrip(4, 0, 0);      /* no offset, no fin */
    check_stream_roundtrip(8, 1000, 1);   /* offset + fin */
    check_stream_roundtrip(0, 0, 1);      /* stream 0, fin, no offset */
}

static void test_frame_stream_truncated(void)
{
    const u8 payload[] = {1, 2, 3};
    quic_stream_frame in = {.stream_id = 4, .offset = 5, .length = 3,
                            .data = payload, .fin = 0};
    u8 buf[32];
    usz w = quic_frame_put_stream(buf, sizeof(buf), &in);
    quic_stream_frame out;
    CHECK(quic_frame_get_stream(buf, w - 1, &out) == 0);
    CHECK(quic_frame_put_stream(buf, 2, &in) == 0);
}

void test_frame(void)
{
    test_frame_simple();
    test_frame_crypto_roundtrip();
    test_frame_crypto_truncated();
    test_frame_stream();
    test_frame_stream_truncated();
}

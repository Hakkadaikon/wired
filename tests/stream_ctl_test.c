#include "test.h"
#include "frame/stream_ctl.c"

/* RESET_STREAM round-trips and decode rejects truncated input. */
static void test_reset_stream(void)
{
    quic_reset_stream_frame in = {.stream_id = 9, .error_code = 0x101,
                                  .final_size = 4096};
    u8 buf[32];
    usz w = quic_reset_stream_encode(buf, sizeof(buf), &in);
    CHECK(w != 0 && buf[0] == QUIC_FRAME_RESET_STREAM);

    quic_reset_stream_frame out;
    usz r = quic_reset_stream_decode(buf, w, &out);
    CHECK(r == w && out.stream_id == 9 && out.error_code == 0x101);
    CHECK(out.final_size == 4096);

    CHECK(quic_reset_stream_decode(buf, w - 1, &out) == 0);
}

/* STOP_SENDING round-trips and decode rejects truncated input. */
static void test_stop_sending(void)
{
    quic_stop_sending_frame in = {.stream_id = 7, .error_code = 0x202};
    u8 buf[32];
    usz w = quic_stop_sending_encode(buf, sizeof(buf), &in);
    CHECK(w != 0 && buf[0] == QUIC_FRAME_STOP_SENDING);

    quic_stop_sending_frame out;
    usz r = quic_stop_sending_decode(buf, w, &out);
    CHECK(r == w && out.stream_id == 7 && out.error_code == 0x202);

    CHECK(quic_stop_sending_decode(buf, w - 1, &out) == 0);
}

void test_stream_ctl(void)
{
    test_reset_stream();
    test_stop_sending();
}

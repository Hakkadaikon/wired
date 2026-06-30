#include "test.h"

/* RFC 9000 19.8: a STREAM frame with offset 0 and no fin sets only the LEN
 * bit; the type byte is 0x0a (0x08 | LEN). It round-trips via get_stream. */
static void test_stream_frame_basic(void)
{
    const u8 data[] = {'h','i'};
    u8 out[32];
    usz olen = 0;
    CHECK(quic_appdata_stream_frame(4, 0, data, sizeof(data), 0,
                                    out, sizeof(out), &olen));
    CHECK(out[0] == (QUIC_FRAME_STREAM_BASE | QUIC_STREAM_LEN));

    quic_stream_frame f;
    CHECK(quic_frame_get_stream(out, olen, &f) == olen);
    CHECK(f.stream_id == 4);
    CHECK(f.offset == 0);
    CHECK(f.length == sizeof(data));
    CHECK(f.fin == 0);
    CHECK(f.data[0] == 'h' && f.data[1] == 'i');
}

/* RFC 9000 19.8: nonzero offset sets OFF, fin sets FIN; both reflected in the
 * type byte and recovered by the decoder. */
static void test_stream_frame_off_fin(void)
{
    const u8 data[] = {'x'};
    u8 out[32];
    usz olen = 0;
    CHECK(quic_appdata_stream_frame(7, 100, data, 1, 1,
                                    out, sizeof(out), &olen));
    CHECK(out[0] == (QUIC_FRAME_STREAM_BASE | QUIC_STREAM_OFF |
                     QUIC_STREAM_LEN | QUIC_STREAM_FIN));

    quic_stream_frame f;
    CHECK(quic_frame_get_stream(out, olen, &f) == olen);
    CHECK(f.stream_id == 7);
    CHECK(f.offset == 100);
    CHECK(f.fin == 1);
}

/* RFC 9000 19.8: OFF without FIN sets type 0x0e (OFF|LEN, FIN clear); the
 * three bits are independent. */
static void test_stream_frame_off_nofin(void)
{
    const u8 data[] = {'q'};
    u8 out[32];
    usz olen = 0;
    CHECK(quic_appdata_stream_frame(3, 5, data, 1, 0,
                                    out, sizeof(out), &olen));
    CHECK(out[0] == (QUIC_FRAME_STREAM_BASE | QUIC_STREAM_OFF |
                     QUIC_STREAM_LEN));
    CHECK((out[0] & QUIC_STREAM_FIN) == 0);

    quic_stream_frame f;
    CHECK(quic_frame_get_stream(out, olen, &f) == olen);
    CHECK(f.offset == 5);
    CHECK(f.fin == 0);
}

/* RFC 9000 19.8: an empty STREAM frame (length 0) still carries the LEN bit
 * with a zero Length varint and round-trips. */
static void test_stream_frame_empty(void)
{
    u8 out[32];
    usz olen = 0;
    CHECK(quic_appdata_stream_frame(8, 0, (const u8 *)"", 0, 1,
                                    out, sizeof(out), &olen));
    CHECK(out[0] == (QUIC_FRAME_STREAM_BASE | QUIC_STREAM_LEN |
                     QUIC_STREAM_FIN));

    quic_stream_frame f;
    CHECK(quic_frame_get_stream(out, olen, &f) == olen);
    CHECK(f.stream_id == 8);
    CHECK(f.length == 0);
    CHECK(f.fin == 1);
}

/* No room: returns 0. */
static void test_stream_frame_overflow(void)
{
    const u8 data[] = {1,2,3,4,5};
    u8 out[2];
    usz olen = 0;
    CHECK(!quic_appdata_stream_frame(0, 0, data, sizeof(data), 0,
                                     out, sizeof(out), &olen));
}

void test_stream_send(void)
{
    test_stream_frame_basic();
    test_stream_frame_off_fin();
    test_stream_frame_off_nofin();
    test_stream_frame_empty();
    test_stream_frame_overflow();
}

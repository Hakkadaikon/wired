#include "test.h"
#include "h3/frame_permit.c"
#include "h3/frame.h"

#define ON(t, k)  CHECK(quic_h3_frame_on_stream((t), (k)) == 1)
#define OFF(t, k) CHECK(quic_h3_frame_on_stream((t), (k)) == 0)

/* DATA and HEADERS: request and push only, never control. */
static void test_data_headers(void)
{
    ON(QUIC_H3_FRAME_DATA, QUIC_H3_STREAM_KIND_REQUEST);
    ON(QUIC_H3_FRAME_DATA, QUIC_H3_STREAM_KIND_PUSH);
    OFF(QUIC_H3_FRAME_DATA, QUIC_H3_STREAM_KIND_CONTROL);
    ON(QUIC_H3_FRAME_HEADERS, QUIC_H3_STREAM_KIND_REQUEST);
    ON(QUIC_H3_FRAME_HEADERS, QUIC_H3_STREAM_KIND_PUSH);
    OFF(QUIC_H3_FRAME_HEADERS, QUIC_H3_STREAM_KIND_CONTROL);
}

/* CANCEL_PUSH / SETTINGS / GOAWAY / MAX_PUSH_ID: control only. */
static void test_control_only(void)
{
    u64 ctl[] = { QUIC_H3_FRAME_CANCEL_PUSH, QUIC_H3_FRAME_SETTINGS,
                  QUIC_H3_FRAME_GOAWAY, QUIC_H3_FRAME_MAX_PUSH_ID };
    for (usz i = 0; i < 4; i++) {
        ON(ctl[i], QUIC_H3_STREAM_KIND_CONTROL);
        OFF(ctl[i], QUIC_H3_STREAM_KIND_REQUEST);
        OFF(ctl[i], QUIC_H3_STREAM_KIND_PUSH);
    }
}

/* PUSH_PROMISE: request stream only (RFC 9114 7.2.5). */
static void test_push_promise(void)
{
    ON(QUIC_H3_FRAME_PUSH_PROMISE, QUIC_H3_STREAM_KIND_REQUEST);
    OFF(QUIC_H3_FRAME_PUSH_PROMISE, QUIC_H3_STREAM_KIND_CONTROL);
    OFF(QUIC_H3_FRAME_PUSH_PROMISE, QUIC_H3_STREAM_KIND_PUSH);
}

/* Unknown and reserved (grease) frame types are permitted on every stream. */
static void test_unknown_permitted(void)
{
    ON(0x21, QUIC_H3_STREAM_KIND_CONTROL);          /* a grease point */
    ON(0x21, QUIC_H3_STREAM_KIND_REQUEST);
    ON(0x21, QUIC_H3_STREAM_KIND_PUSH);
    ON(0x1234, QUIC_H3_STREAM_KIND_CONTROL);        /* unknown */
    ON(0x1234, QUIC_H3_STREAM_KIND_REQUEST);
}

void test_frame_permit(void)
{
    test_data_headers();
    test_control_only();
    test_push_promise();
    test_unknown_permitted();
}

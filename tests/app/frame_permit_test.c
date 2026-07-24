#include "app/http3/core/h3/frame.h"
#include "test.h"

#define ON(t, k) CHECK(quic_h3_frame_on_stream((t), (k)) == 1)
#define OFF(t, k) CHECK(quic_h3_frame_on_stream((t), (k)) == 0)

/* DATA and HEADERS: request and push only, never control. */
static void test_data_headers(void) {
  ON(QUIC_H3_FRAME_DATA, QUIC_H3_STREAM_KIND_REQUEST);
  ON(QUIC_H3_FRAME_DATA, QUIC_H3_STREAM_KIND_PUSH);
  OFF(QUIC_H3_FRAME_DATA, QUIC_H3_STREAM_KIND_CONTROL);
  ON(QUIC_H3_FRAME_HEADERS, QUIC_H3_STREAM_KIND_REQUEST);
  ON(QUIC_H3_FRAME_HEADERS, QUIC_H3_STREAM_KIND_PUSH);
  OFF(QUIC_H3_FRAME_HEADERS, QUIC_H3_STREAM_KIND_CONTROL);
}

/* CANCEL_PUSH / SETTINGS / GOAWAY / MAX_PUSH_ID: control only. */
static void test_control_only(void) {
  u64 ctl[] = {
      QUIC_H3_FRAME_CANCEL_PUSH, QUIC_H3_FRAME_SETTINGS, QUIC_H3_FRAME_GOAWAY,
      QUIC_H3_FRAME_MAX_PUSH_ID};
  for (usz i = 0; i < 4; i++) {
    ON(ctl[i], QUIC_H3_STREAM_KIND_CONTROL);
    OFF(ctl[i], QUIC_H3_STREAM_KIND_REQUEST);
    OFF(ctl[i], QUIC_H3_STREAM_KIND_PUSH);
  }
}

/* PUSH_PROMISE: request stream only (RFC 9114 7.2.5). */
static void test_push_promise(void) {
  ON(QUIC_H3_FRAME_PUSH_PROMISE, QUIC_H3_STREAM_KIND_REQUEST);
  OFF(QUIC_H3_FRAME_PUSH_PROMISE, QUIC_H3_STREAM_KIND_CONTROL);
  OFF(QUIC_H3_FRAME_PUSH_PROMISE, QUIC_H3_STREAM_KIND_PUSH);
}

/* RFC 9114 7.2.5 / 9114-067: this SDK is server-only and never sends
 * PUSH_PROMISE, so receiving one at all -- on any stream -- is always an
 * H3_FRAME_UNEXPECTED connection error; every other defined frame type
 * (including CANCEL_PUSH/MAX_PUSH_ID, the OTHER push-related frames) is
 * unaffected. */
static void test_recv_push_promise_always_rejected(void) {
  CHECK(quic_h3_frame_recv_ok(QUIC_H3_FRAME_PUSH_PROMISE) == 0);
  CHECK(quic_h3_frame_recv_ok(QUIC_H3_FRAME_DATA) == 1);
  CHECK(quic_h3_frame_recv_ok(QUIC_H3_FRAME_HEADERS) == 1);
  CHECK(quic_h3_frame_recv_ok(QUIC_H3_FRAME_SETTINGS) == 1);
  CHECK(quic_h3_frame_recv_ok(QUIC_H3_FRAME_CANCEL_PUSH) == 1);
  CHECK(quic_h3_frame_recv_ok(QUIC_H3_FRAME_GOAWAY) == 1);
  CHECK(quic_h3_frame_recv_ok(QUIC_H3_FRAME_MAX_PUSH_ID) == 1);
  CHECK(quic_h3_frame_recv_ok(0x21) == 1); /* grease point, unaffected */
}

/* RFC 9114 7.2.8 / 9114-073: HTTP/2-only reserved frame types (0x02, 0x06,
 * 0x08, 0x09) are never safe to receive -- unlike a true gap in the permit
 * table (unknown/grease, tolerated on every stream by test_unknown_permitted
 * below), HTTP/3 defines no use for these code points at all. */
static void test_recv_http2_only_reserved_rejected(void) {
  CHECK(quic_h3_frame_recv_ok(0x02) == 0);
  CHECK(quic_h3_frame_recv_ok(0x06) == 0);
  CHECK(quic_h3_frame_recv_ok(0x08) == 0);
  CHECK(quic_h3_frame_recv_ok(0x09) == 0);
  /* neighbors just outside the reserved set stay unaffected */
  CHECK(quic_h3_frame_recv_ok(0x07) == 1); /* GOAWAY, a real HTTP/3 type */
  CHECK(quic_h3_frame_recv_ok(0x0a) == 1); /* a true gap: unknown/grease */
}

/* Unknown and reserved (grease) frame types are permitted on every stream. */
static void test_unknown_permitted(void) {
  ON(0x21, QUIC_H3_STREAM_KIND_CONTROL); /* a grease point */
  ON(0x21, QUIC_H3_STREAM_KIND_REQUEST);
  ON(0x21, QUIC_H3_STREAM_KIND_PUSH);
  ON(0x1234, QUIC_H3_STREAM_KIND_CONTROL); /* unknown */
  ON(0x1234, QUIC_H3_STREAM_KIND_REQUEST);
}

void test_frame_permit(void) {
  test_data_headers();
  test_control_only();
  test_push_promise();
  test_recv_push_promise_always_rejected();
  test_recv_http2_only_reserved_rejected();
  test_unknown_permitted();
}

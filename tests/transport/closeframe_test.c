#include "transport/stream/flow/flowviol/closeframe.h"

#include "common/diag/error/codes.h"
#include "test.h"
#include "transport/packet/frame/frame/frame.h"

static void test_closeframe_wire(void) {
  static const u8       reason[] = {'f', 'l', 'o', 'w'};
  u8                    buf[64];
  quic_conn_close_frame got;
  quic_flowviol_err     e = {
      QUIC_EC_FLOW_CONTROL_ERROR,
      QUIC_FRAME_CONN_CLOSE_TPT,
      {reason, sizeof reason}};
  quic_obuf ob = quic_obuf_of(buf, sizeof buf);

  CHECK(quic_flowviol_close_frame(&e, &ob) == 1);
  usz len = ob.len;
  CHECK(len > 0);
  CHECK(buf[0] == QUIC_FRAME_CONN_CLOSE_TPT); /* transport variant 0x1c */

  /* the error code, triggering frame type, and reason land on the wire */
  CHECK(quic_frame_get_conn_close(buf, len, &got) == len);
  CHECK(got.is_app == 0);
  CHECK(got.error_code == QUIC_EC_FLOW_CONTROL_ERROR);
  CHECK(got.frame_type == QUIC_FRAME_CONN_CLOSE_TPT);
  CHECK(got.reason_len == sizeof reason);
  CHECK(got.reason[0] == 'f' && got.reason[3] == 'w');
}

static void test_closeframe_overflow(void) {
  u8                buf[2];
  quic_flowviol_err e  = {QUIC_EC_STREAM_LIMIT_ERROR, 0x12, {0, 0}};
  quic_obuf         ob = quic_obuf_of(buf, sizeof buf);
  CHECK(quic_flowviol_close_frame(&e, &ob) == 0);
}

void test_closeframe(void) {
  test_closeframe_wire();
  test_closeframe_overflow();
}

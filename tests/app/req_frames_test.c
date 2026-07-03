#include "test.h"

/* RFC 9114 4.1: a request stream begins with a HEADERS frame. */
static void test_req_frames_headers_first(void) {
  u8        fs[] = {0xaa, 0xbb, 0xcc};
  u8        buf[16];
  quic_obuf ob = {buf, sizeof buf, 0};
  usz       n  = quic_h3_frame_put(
      &ob, QUIC_H3_FRAME_HEADERS, quic_span_of(fs, sizeof fs));
  quic_span out = {0, 0};
  CHECK(quic_h3req_recv_first_headers(quic_span_of(buf, n), &out) == 1);
  CHECK(out.n == sizeof(fs));
  CHECK(out.p[0] == 0xaa && out.p[2] == 0xcc);
}

static void test_req_frames_data_first(void) {
  u8        body[] = {0x01};
  u8        buf[16];
  quic_obuf ob = {buf, sizeof buf, 0};
  usz       n  = quic_h3_frame_put(
      &ob, QUIC_H3_FRAME_DATA, quic_span_of(body, sizeof body));
  quic_span out = {0, 0};
  CHECK(quic_h3req_recv_first_headers(quic_span_of(buf, n), &out) == 0);
}

static void test_req_frames_truncated(void) {
  u8        buf[1] = {QUIC_H3_FRAME_HEADERS};
  quic_span out    = {0, 0};
  /* length varint missing -> no complete frame. */
  CHECK(quic_h3req_recv_first_headers(quic_span_of(buf, 1), &out) == 0);
}

void test_req_frames(void) {
  test_req_frames_headers_first();
  test_req_frames_data_first();
  test_req_frames_truncated();
}

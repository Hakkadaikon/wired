#include "test.h"

/* The canonical order HEADERS, DATA*, trailing HEADERS is accepted. */
static void test_reqstream_ok_order(void) {
  h3_req_state s = QUIC_H3_REQ_START;
  CHECK(h3_reqstream_frame(&s, QUIC_H3_FRAME_HEADERS) == 1);
  CHECK(s == QUIC_H3_REQ_HEADERS);
  CHECK(h3_reqstream_frame(&s, QUIC_H3_FRAME_DATA) == 1);
  CHECK(h3_reqstream_frame(&s, QUIC_H3_FRAME_DATA) == 1); /* DATA repeats */
  CHECK(s == QUIC_H3_REQ_DATA);
  CHECK(h3_reqstream_frame(&s, QUIC_H3_FRAME_HEADERS) == 1); /* trailer */
  CHECK(s == QUIC_H3_REQ_TRAILERS);
}

/* HEADERS then trailing HEADERS with no DATA in between is valid. */
static void test_reqstream_no_data(void) {
  h3_req_state s = QUIC_H3_REQ_START;
  CHECK(h3_reqstream_frame(&s, QUIC_H3_FRAME_HEADERS) == 1);
  CHECK(h3_reqstream_frame(&s, QUIC_H3_FRAME_HEADERS) == 1);
  CHECK(s == QUIC_H3_REQ_TRAILERS);
}

/* DATA before the leading HEADERS is a FRAME_UNEXPECTED violation. */
static void test_reqstream_data_first(void) {
  h3_req_state s = QUIC_H3_REQ_START;
  CHECK(h3_reqstream_frame(&s, QUIC_H3_FRAME_DATA) == 0);
  CHECK(s == QUIC_H3_REQ_START); /* state unchanged on violation */
}

/* A trailing HEADERS terminates the stream; nothing may follow. */
static void test_reqstream_after_trailers(void) {
  h3_req_state s = QUIC_H3_REQ_START;
  h3_reqstream_frame(&s, QUIC_H3_FRAME_HEADERS);
  h3_reqstream_frame(&s, QUIC_H3_FRAME_HEADERS); /* trailer */
  CHECK(h3_reqstream_frame(&s, QUIC_H3_FRAME_DATA) == 0);
  CHECK(h3_reqstream_frame(&s, QUIC_H3_FRAME_HEADERS) == 0); /* 3rd HEADERS */
  CHECK(s == QUIC_H3_REQ_TRAILERS);
}

/* A control-only frame type (e.g. SETTINGS) is not valid on a request stream.
 */
static void test_reqstream_wrong_type(void) {
  h3_req_state s = QUIC_H3_REQ_START;
  CHECK(h3_reqstream_frame(&s, QUIC_H3_FRAME_SETTINGS) == 0);
  CHECK(s == QUIC_H3_REQ_START);
}

void test_reqstream(void) {
  test_reqstream_ok_order();
  test_reqstream_no_data();
  test_reqstream_data_first();
  test_reqstream_after_trailers();
  test_reqstream_wrong_type();
}

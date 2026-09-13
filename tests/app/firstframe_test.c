#include "test.h"

/* The control stream's first frame must be SETTINGS. */
static void test_firstframe_control(void) {
  CHECK(h3_first_frame_ok(H3_STREAM_KIND_CONTROL, H3_FRAME_SETTINGS) == 1);
  CHECK(h3_first_frame_ok(H3_STREAM_KIND_CONTROL, H3_FRAME_HEADERS) == 0);
  CHECK(h3_first_frame_ok(H3_STREAM_KIND_CONTROL, H3_FRAME_DATA) == 0);
}

/* A request stream's first frame must be HEADERS. */
static void test_firstframe_request(void) {
  CHECK(h3_first_frame_ok(H3_STREAM_KIND_REQUEST, H3_FRAME_HEADERS) == 1);
  CHECK(h3_first_frame_ok(H3_STREAM_KIND_REQUEST, H3_FRAME_DATA) == 0);
  CHECK(h3_first_frame_ok(H3_STREAM_KIND_REQUEST, H3_FRAME_SETTINGS) == 0);
}

/* Pinning: RFC 9114 6.2.1 -- a control stream that sends anything other than
 * SETTINGS first must be rejected, never accepted "after" some other frame
 * type is seen first (V-0429/CVE-2024-24990 class). */
static void test_h3_first_frame_settings_before_other_rejected(void) {
  static const u64 others[] = {
      H3_FRAME_DATA, H3_FRAME_HEADERS, H3_FRAME_GOAWAY, H3_FRAME_CANCEL_PUSH};
  for (usz i = 0; i < sizeof(others) / sizeof(others[0]); i++)
    CHECK(h3_first_frame_ok(H3_STREAM_KIND_CONTROL, others[i]) == 0);
  CHECK(h3_first_frame_ok(H3_STREAM_KIND_CONTROL, H3_FRAME_SETTINGS) == 1);
}

void test_firstframe(void) {
  test_firstframe_control();
  test_firstframe_request();
  test_h3_first_frame_settings_before_other_rejected();
}

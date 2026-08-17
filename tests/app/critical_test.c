#include "test.h"

/* Control, QPACK encoder and QPACK decoder streams are critical; push is not.
 */
static void test_critical_classify(void) {
  CHECK(h3_stream_is_critical(H3_STREAM_CONTROL) == 1);
  CHECK(h3_stream_is_critical(H3_STREAM_QPACK_ENCODER) == 1);
  CHECK(h3_stream_is_critical(H3_STREAM_QPACK_DECODER) == 1);
  CHECK(h3_stream_is_critical(H3_STREAM_PUSH) == 0);
  CHECK(h3_stream_is_critical(0x21) == 0); /* reserved/grease */
}

/* Closing a critical stream maps to H3_CLOSED_CRITICAL_STREAM; else no error.
 */
static void test_critical_close_error(void) {
  CHECK(
      h3_critical_close_error(H3_STREAM_CONTROL) == H3_CLOSED_CRITICAL_STREAM);
  CHECK(
      h3_critical_close_error(H3_STREAM_QPACK_DECODER) ==
      H3_CLOSED_CRITICAL_STREAM);
  CHECK(h3_critical_close_error(H3_STREAM_PUSH) == 0);
}

void test_critical(void) {
  test_critical_classify();
  test_critical_close_error();
}

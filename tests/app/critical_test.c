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

/* Pinning: CVE-2024-35200-class NULL-deref -- an unclassified/unknown
 * stream type (neither control, QPACK encoder/decoder, nor push) must
 * classify cleanly to "not critical" and "no close error", a pure value
 * computation with no pointer dereference, so a caller gating per-stream
 * state on this classification never dereferences anything on a stream
 * type it does not recognize (V-0432). */
static void test_srvloop_unclassified_stream_frame_no_deref(void) {
  static const u64 unclassified[] = {
      0x21, 0x40, 0x1000, (u64)-1, H3_STREAM_PUSH};
  for (usz i = 0; i < sizeof(unclassified) / sizeof(unclassified[0]); i++) {
    u64 t = unclassified[i];
    CHECK(h3_stream_is_critical(t) == 0);
    CHECK(h3_critical_close_error(t) == 0);
  }
}

void test_critical(void) {
  test_critical_classify();
  test_critical_close_error();
  test_srvloop_unclassified_stream_frame_no_deref();
}

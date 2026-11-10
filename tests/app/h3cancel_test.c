#include "test.h"

/* CANCEL_PUSH codec (RFC 9114 7.2.3) is reused from h3/frame.c. */
static void test_h3cancel_push_roundtrip(void) {
  u8  out[8];
  u64 id = 0;
  usz n  = h3_cancel_push_put(out, sizeof out, 0x4142);

  CHECK(n > 0);
  CHECK(out[0] == H3_FRAME_CANCEL_PUSH);
  CHECK(h3_cancel_push_get(out, n, &id) == n);
  CHECK(id == 0x4142);
}

static void test_h3cancel_push_truncated(void) {
  u8  out[8];
  usz n = h3_cancel_push_put(out, sizeof out, 0x4142);

  CHECK(h3_cancel_push_get(out, n - 1, &(u64){0}) == 0);
}

static void test_h3cancel_error_code_value(void) {
  CHECK(H3_REQUEST_CANCELLED == 0x010c);
}

void test_h3cancel(void) {
  test_h3cancel_push_roundtrip();
  test_h3cancel_push_truncated();
  test_h3cancel_error_code_value();
}

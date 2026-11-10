#include "app/http3/core/h3/frame.h"
#include "test.h"

/* RFC 9114 8.1 / 9114-077: h3_error_send_value substitutes grease_id for
 * H3_NO_ERROR only when grease_id is non-zero, and never touches any other
 * code -- the deterministic half of "send grease with some probability" (the
 * probability itself lives in whoever picks grease_id, not here). */
static void test_error_send_value(void) {
  /* grease_id == 0: H3_NO_ERROR passes through unchanged */
  CHECK(h3_error_send_value(H3_NO_ERROR, 0) == H3_NO_ERROR);
  /* non-zero grease_id substitutes for H3_NO_ERROR */
  {
    u64 gid = 0x21 + 0x1f * 5;
    CHECK(h3_is_reserved(gid) == 1);
    CHECK(h3_error_send_value(H3_NO_ERROR, gid) == gid);
  }
  /* any other code is never substituted, grease_id or not */
  CHECK(
      h3_error_send_value(H3_REQUEST_CANCELLED, 0x21 + 0x1f) ==
      H3_REQUEST_CANCELLED);
  CHECK(h3_error_send_value(H3_INTERNAL_ERROR, 0) == H3_INTERNAL_ERROR);
}

void test_errclass(void) { test_error_send_value(); }

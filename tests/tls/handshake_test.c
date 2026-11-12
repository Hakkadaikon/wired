#include "test.h"

static void test_hs_truncated(void) {
  u8       type;
  usz      body_len;
  const u8 bad[3] = {1, 0, 5};
  CHECK(hs_parse(wired_span_of(bad, 3), &type, &body_len) == 0);
  /* claims body 100 but only 4 bytes present */
  const u8 bad2[4] = {1, 0, 0, 100};
  CHECK(hs_parse(wired_span_of(bad2, 4), &type, &body_len) == 0);
}

/* A handshake header needs 4 bytes. */
static void test_hs_short_buffers(void) {
  u8 out[4];
  CHECK(hs_begin(out, 3, HS_CLIENT_HELLO) == 0);
  CHECK(hs_begin(out, 4, HS_CLIENT_HELLO) == 4 && out[0] == HS_CLIENT_HELLO);
}

void test_handshake(void) {
  test_hs_short_buffers();
  test_hs_truncated();
}

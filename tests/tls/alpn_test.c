#include "test.h"

static void test_alpn_h3_encode(void) {
  const u8   h3[] = {0x68, 0x33};
  u8         buf[16];
  wired_obuf ob = obuf_of(buf, sizeof(buf));
  usz        w  = tls_alpn_encode(&ob, wired_span_of(h3, sizeof(h3)));
  CHECK(w == 5);
  CHECK(buf[3] == 0x68 && buf[4] == 0x33);
  /* wire: list length 0x0003, name length 0x02 */
  CHECK(buf[0] == 0x00 && buf[1] == 0x03 && buf[2] == 0x02);
}

static void test_alpn_encode_guard(void) {
  const u8   h3[] = {0x68, 0x33};
  u8         buf[4];
  wired_obuf ob = obuf_of(buf, sizeof(buf));
  CHECK(tls_alpn_encode(&ob, wired_span_of(h3, sizeof(h3))) == 0);
  CHECK(tls_alpn_encode(&ob, wired_span_of(h3, 0)) == 0);
}

void test_alpn(void) {
  test_alpn_h3_encode();
  test_alpn_encode_guard();
}

#include "test.h"

static void test_tpext_roundtrip(void) {
  u8         tp[] = {0x00, 0x08, 0x12, 0x34};
  u8         buf[32];
  wired_span out;
  wired_obuf ob = obuf_of(buf, sizeof(buf));
  usz        w  = tpext_encode(&ob, wired_span_of(tp, sizeof(tp)));
  usz        r  = tpext_decode(wired_span_of(buf, w), &out);
  CHECK(w == 4 + sizeof(tp) && r == w);
  CHECK(out.n == sizeof(tp) && out.p == buf + 4);
  for (usz i = 0; i < sizeof(tp); i++) CHECK(out.p[i] == tp[i]);
  /* wire framing: type 0x0039, length */
  CHECK(buf[0] == 0x00 && buf[1] == 0x39);
  CHECK(buf[2] == 0x00 && buf[3] == (u8)sizeof(tp));
}

static void test_tpext_empty(void) {
  u8         buf[8];
  wired_span out;
  wired_obuf ob = obuf_of(buf, sizeof(buf));
  usz        w  = tpext_encode(&ob, wired_span_of(0, 0));
  usz        r  = tpext_decode(wired_span_of(buf, w), &out);
  CHECK(w == 4 && r == 4 && out.n == 0);
}

static void test_tpext_wrong_type(void) {
  u8         buf[8] = {0x00, 0x38, 0x00, 0x00};
  wired_span out;
  CHECK(tpext_decode(wired_span_of(buf, 4), &out) == 0);
}

static void test_tpext_bad_len(void) {
  u8         buf[16];
  wired_span out;
  wired_obuf ob = obuf_of(buf, sizeof(buf));
  usz        w  = tpext_encode(&ob, wired_span_of((const u8*)"abc", 3));
  /* length field claims 3 but only 2 data bytes are readable */
  CHECK(tpext_decode(wired_span_of(buf, w - 1), &out) == 0);
  /* no room to encode */
  {
    wired_obuf small = obuf_of(buf, 4);
    CHECK(tpext_encode(&small, wired_span_of((const u8*)"abc", 3)) == 0);
  }
}

void test_tpext(void) {
  test_tpext_roundtrip();
  test_tpext_empty();
  test_tpext_wrong_type();
  test_tpext_bad_len();
}

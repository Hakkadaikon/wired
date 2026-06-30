#include "test.h"

static void test_inittoken_roundtrip(void) {
  u8        tok[] = {0xDE, 0xAD, 0xBE, 0xEF};
  u8        buf[32];
  const u8 *out;
  usz       olen;
  usz       w = quic_inittoken_put(buf, sizeof(buf), tok, sizeof(tok));
  usz       r = quic_inittoken_get(buf, w, &out, &olen);
  CHECK(w == 1 + sizeof(tok) && r == w && olen == sizeof(tok));
  for (usz i = 0; i < sizeof(tok); i++) CHECK(out[i] == tok[i]);
}

static void test_inittoken_empty(void) {
  u8        buf[8];
  const u8 *out;
  usz       olen;
  usz       w = quic_inittoken_put(buf, sizeof(buf), (const u8 *)0, 0);
  usz       r = quic_inittoken_get(buf, w, &out, &olen);
  CHECK(w == 1 && r == 1 && olen == 0 && out == (const u8 *)0);
  CHECK(buf[0] == 0x00);
}

static void test_inittoken_bounds(void) {
  u8        tok[] = {1, 2, 3};
  u8        buf[8];
  const u8 *out;
  usz       olen;
  usz       w = quic_inittoken_put(buf, sizeof(buf), tok, sizeof(tok));
  /* token bytes truncated */
  CHECK(quic_inittoken_get(buf, w - 1, &out, &olen) == 0);
  /* no room to encode body */
  CHECK(quic_inittoken_put(buf, 2, tok, sizeof(tok)) == 0);
}

void test_inittoken(void) {
  test_inittoken_roundtrip();
  test_inittoken_empty();
  test_inittoken_bounds();
}

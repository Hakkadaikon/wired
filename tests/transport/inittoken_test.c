#include "test.h"

static void test_inittoken_roundtrip(void) {
  u8        tok[] = {0xDE, 0xAD, 0xBE, 0xEF};
  u8        buf[32];
  quic_span out;
  usz w = quic_inittoken_put(buf, sizeof(buf), quic_span_of(tok, sizeof(tok)));
  usz r = quic_inittoken_get(buf, w, &out);
  CHECK(w == 1 + sizeof(tok) && r == w && out.n == sizeof(tok));
  for (usz i = 0; i < sizeof(tok); i++) CHECK(out.p[i] == tok[i]);
}

static void test_inittoken_empty(void) {
  u8        buf[8];
  quic_span out;
  usz w = quic_inittoken_put(buf, sizeof(buf), quic_span_of((const u8 *)0, 0));
  usz r = quic_inittoken_get(buf, w, &out);
  CHECK(w == 1 && r == 1 && out.n == 0 && out.p == (const u8 *)0);
  CHECK(buf[0] == 0x00);
}

static void test_inittoken_bounds(void) {
  u8        tok[] = {1, 2, 3};
  u8        buf[8];
  quic_span out;
  usz w = quic_inittoken_put(buf, sizeof(buf), quic_span_of(tok, sizeof(tok)));
  /* token bytes truncated */
  CHECK(quic_inittoken_get(buf, w - 1, &out) == 0);
  /* no room to encode body */
  CHECK(quic_inittoken_put(buf, 2, quic_span_of(tok, sizeof(tok))) == 0);
}

void test_inittoken(void) {
  test_inittoken_roundtrip();
  test_inittoken_empty();
  test_inittoken_bounds();
}

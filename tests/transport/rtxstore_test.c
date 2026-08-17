#include "test.h"

static void test_rtxstore_store_get_roundtrip(void) {
  rtxbytes   st;
  const u8   frame[] = {0x08, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'};
  wired_span got;

  rtxbytes_init(&st);
  CHECK(rtxbytes_store(&st, 7, wired_span_of(frame, sizeof frame)) == 1);
  CHECK(rtxbytes_get(&st, 7, &got) == 1);
  CHECK(got.n == sizeof frame);
  for (usz i = 0; i < sizeof frame; i++) CHECK(got.p[i] == frame[i]);
}

static void test_rtxstore_miss(void) {
  rtxbytes   st;
  const u8   frame[] = {0x01};
  wired_span got;

  rtxbytes_init(&st);
  rtxbytes_store(&st, 1, wired_span_of(frame, sizeof frame));
  CHECK(rtxbytes_get(&st, 99, &got) == 0);
}

static void test_rtxstore_too_large(void) {
  rtxbytes  st;
  static u8 big[RTXBYTES_FRAME + 1];

  rtxbytes_init(&st);
  CHECK(rtxbytes_store(&st, 1, wired_span_of(big, sizeof big)) == 0);
}

void test_rtxstore(void) {
  test_rtxstore_store_get_roundtrip();
  test_rtxstore_miss();
  test_rtxstore_too_large();
}

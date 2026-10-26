#include "test.h"

/* The grease_quic_bit parameter is encoded with an empty value. */
static void test_grease_param(void) {
  u8  buf[8];
  usz w = grease_encode(buf, sizeof(buf));
  CHECK(w != 0);
  CHECK(buf[w - 1] == 0); /* zero-length value */
}

void test_grease(void) { test_grease_param(); }

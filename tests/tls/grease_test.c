#include "test.h"

/* The grease_quic_bit parameter is encoded with an empty value. */
static void test_grease_param(void) {
  u8  buf[8];
  usz w = grease_encode(buf, sizeof(buf));
  CHECK(w != 0);
  CHECK(buf[w - 1] == 0); /* zero-length value */
  /* RFC 9287 3: id 0x2ab2 is a 2-byte varint; no room for the length */
  CHECK(grease_encode(buf, 2) == 0);
}

void test_grease(void) { test_grease_param(); }

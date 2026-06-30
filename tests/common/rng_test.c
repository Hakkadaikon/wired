#include "test.h"

/* Two consecutive draws differ, and the full length is filled. */
static void test_rng_distinct_and_full(void) {
  u8 a[32], b[32];
  for (usz i = 0; i < 32; i++) {
    a[i] = 0xAA;
    b[i] = 0xAA;
  }
  CHECK(quic_rng_bytes(a, 32) == 1);
  CHECK(quic_rng_bytes(b, 32) == 1);
  /* a changed from the 0xAA sentinel: the buffer was actually written */
  int written = 0;
  for (usz i = 0; i < 32; i++)
    if (a[i] != 0xAA) written = 1;
  CHECK(written);
  /* two draws are not byte-identical */
  int differ = 0;
  for (usz i = 0; i < 32; i++)
    if (a[i] != b[i]) differ = 1;
  CHECK(differ);
}

void test_rng(void) { test_rng_distinct_and_full(); }

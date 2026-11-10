#include "test.h"

/* Challenge data fills its full width and differ between draws. */
static void test_challenge_distinct(void) {
  u8 a[8], b[8];
  for (usz i = 0; i < 8; i++) {
    a[i] = 0;
    b[i] = 0;
  }
  CHECK(challenge_generate(a) == 1);
  CHECK(challenge_generate(b) == 1);
  int differ = 0;
  for (usz i = 0; i < 8; i++) {
    if (a[i] != b[i]) {
      differ = 1;
    }
  }
  CHECK(differ);
}

void test_challenge(void) { test_challenge_distinct(); }

#include "test.h"

/* A fresh state permits no pushes. */
static void test_push_init(void) {
  h3_push_state s;
  h3_push_init(&s);
  CHECK(s.max == 0);
}

/* Raising the maximum permits IDs strictly below it. */
static void test_push_set_max(void) {
  h3_push_state s;
  h3_push_init(&s);
  CHECK(h3_push_set_max(&s, 3) == 1);
  CHECK(s.max == 3);
}

/* The maximum may be raised again but never lowered. */
static void test_push_monotonic(void) {
  h3_push_state s;
  h3_push_init(&s);
  CHECK(h3_push_set_max(&s, 5) == 1);
  CHECK(h3_push_set_max(&s, 5) == 1);  /* equal holds */
  CHECK(h3_push_set_max(&s, 10) == 1); /* raise */
  CHECK(h3_push_set_max(&s, 9) == 0);  /* lower rejected */
  CHECK(s.max == 10);                  /* unchanged */
}

void test_pushid(void) {
  test_push_init();
  test_push_set_max();
  test_push_monotonic();
}

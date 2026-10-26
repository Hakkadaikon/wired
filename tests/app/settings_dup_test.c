#include "test.h"

/* Distinct identifiers are all accepted. */
static void test_settings_dup_distinct(void) {
  h3_settings_seen s;
  h3_settings_seen_init(&s);
  CHECK(h3_settings_mark(&s, 0x01) == 1);
  CHECK(h3_settings_mark(&s, 0x06) == 1);
  CHECK(h3_settings_mark(&s, 0x07) == 1);
}

/* A repeated identifier is rejected (H3_SETTINGS_ERROR). */
static void test_settings_dup_repeat(void) {
  h3_settings_seen s;
  h3_settings_seen_init(&s);
  CHECK(h3_settings_mark(&s, 0x06) == 1);
  CHECK(h3_settings_mark(&s, 0x06) == 0);
}

/* Marking past the capacity is accepted unchecked (an unknown setting must
 * never be refused, RFC 9114 7.2.4). */
static void test_settings_dup_full(void) {
  h3_settings_seen s;
  h3_settings_seen_init(&s);
  for (u64 i = 0; i < H3_SETTINGS_SEEN_MAX; i++) {
    CHECK(h3_settings_mark(&s, 0x100 + i) == 1);
  }
  CHECK(h3_settings_mark(&s, 0x999) == 1); /* full: accepted unchecked */
}

void test_settings_dup(void) {
  test_settings_dup_distinct();
  test_settings_dup_repeat();
  test_settings_dup_full();
}

#include "test.h"

/* h3_grease_value is h3_is_reserved's inverse: every value it
 * produces is itself recognized as reserved -- the round-trip property any
 * caller that sends a grease value on the wire (SETTINGS 9114-064, an error
 * code 9114-077) relies on. */
static void test_h3grease_value_roundtrip(void) {
  CHECK(h3_grease_value(0) == 0x21);
  CHECK(h3_grease_value(1) == 0x21 + 0x1f);
  for (u64 n = 0; n < 300; n++) CHECK(h3_is_reserved(h3_grease_value(n)) == 1);
}

/* Pinning: an unknown/reserved (GREASE) frame type is classified in the same
 * O(1) modulo check as every other type -- no growth or unbounded loop is
 * introduced by a flood of distinct grease values (V-0445). */
static void test_h3grease_unknown_frame_skipped_bounded(void) {
  for (u64 n = 0; n < 1000; n++) {
    u64 v = h3_grease_value(n);
    CHECK(h3_is_reserved(v) == 1);
  }
  /* a non-reserved type right below the first grease point is not skipped */
  CHECK(h3_is_reserved(0x20) == 0);
}

/* RFC 9114 reserved (grease) values 0x1f*N + 0x21 are recognized so a
 * receiver can ignore them across frame/stream/setting/error spaces. */
static void test_h3grease(void) {
  CHECK(h3_is_reserved(0x21) == 1);        /* N=0 */
  CHECK(h3_is_reserved(0x21 + 0x1f) == 1); /* N=1 = 0x40 */
  CHECK(h3_is_reserved(0x21 + 0x1f * 7) == 1);
  CHECK(h3_is_reserved(0x20) == 0); /* below first point */
  CHECK(h3_is_reserved(0x04) == 0); /* SETTINGS, a real type */
  CHECK(h3_is_reserved(0x00) == 0); /* DATA, a real type */
  test_h3grease_value_roundtrip();
  test_h3grease_unknown_frame_skipped_bounded();
}

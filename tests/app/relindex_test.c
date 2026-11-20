#include "app/qpack/qpack/relindex.h"

#include "test.h"

/* RFC 9204 3.2.5: relative index 0 is the entry just below Base, and the
 * absolute index decreases as the relative index grows. */
static void test_qpack_rel_to_abs(void) {
  u64 abs = 99;
  CHECK(qpack_rel_to_abs(6, 0, &abs) && abs == 5);
  CHECK(qpack_rel_to_abs(6, 5, &abs) && abs == 0);
}

/* RFC 9204 3.2.5: a relative index of base or more reaches below absolute
 * index 0 -- the underflow is rejected instead of wrapping. */
static void test_qpack_rel_to_abs_underflow(void) {
  u64 abs;
  CHECK(!qpack_rel_to_abs(6, 6, &abs));
  CHECK(!qpack_rel_to_abs(0, 0, &abs));
  CHECK(!qpack_rel_to_abs(6, (u64)-1, &abs));
}

/* RFC 9204 3.2.6: post-base index 0 is the entry at Base, growing upward. */
static void test_qpack_postbase_to_abs(void) {
  u64 abs = 99;
  CHECK(qpack_postbase_to_abs(6, 0, &abs) && abs == 6);
  CHECK(qpack_postbase_to_abs(6, 3, &abs) && abs == 9);
  /* The topmost representable absolute index is still accepted. */
  CHECK(qpack_postbase_to_abs((u64)-1 - 3, 3, &abs) && abs == (u64)-1);
}

/* RFC 9204 3.2.6: base + postbase past 2^64-1 wraps -- rejected. */
static void test_qpack_postbase_to_abs_overflow(void) {
  u64 abs;
  CHECK(!qpack_postbase_to_abs((u64)1 << 63, (u64)1 << 63, &abs));
  CHECK(!qpack_postbase_to_abs((u64)-1, 1, &abs));
}

void test_relindex(void) {
  test_qpack_rel_to_abs();
  test_qpack_rel_to_abs_underflow();
  test_qpack_postbase_to_abs();
  test_qpack_postbase_to_abs_overflow();
}

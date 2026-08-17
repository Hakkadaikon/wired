#include "test.h"

static void test_crypto_offset_ok(void) {
  CHECK(crypto_offset_ok(0, 100, 100) == 1);     /* exact fit */
  CHECK(crypto_offset_ok(50, 50, 100) == 1);     /* ends at limit */
  CHECK(crypto_offset_ok(50, 51, 100) == 0);     /* one past */
  CHECK(crypto_offset_ok(100, 0, 100) == 1);     /* empty at limit */
  CHECK(crypto_offset_ok((u64)-1, 1, 100) == 0); /* wrap rejected */
}

static void test_crypto_contiguous(void) {
  CHECK(crypto_contiguous(10, 10) == 1); /* abuts: no gap */
  CHECK(crypto_contiguous(10, 5) == 1);  /* overlap allowed */
  CHECK(crypto_contiguous(10, 11) == 0); /* gap at [10,11) */
  CHECK(crypto_contiguous(0, 0) == 1);   /* start */
}

void test_crypto_offset(void) {
  test_crypto_offset_ok();
  test_crypto_contiguous();
}
